#!/usr/bin/env python3
"""rackfan – PWM fan control for a Noctua NF-A12x25 5V PWM fan on a Raspberry Pi 4.

Wiring (outer pin row):  pin 4 = 5 V (yellow), pin 6 = GND (black),
                         pin 12 = GPIO18 PWM (blue), pin 18 = GPIO24 tachometer (green).

The fan follows the hottest CPU temperature of your servers (5-minute average from
Prometheus) and exposes speed and duty cycle at http://<pi>:9101/metrics.

Test:     sudo python3 /usr/local/bin/rackfan.py --test
Service:  rackfan.service (systemd)

Settings below can also be set as environment variables in the service file
(RACKFAN_PROM, RACKFAN_QUERY).
"""
import glob, json, os, signal, sys, threading, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ===================== settings =====================
# Prometheus query API – here through the panel's read-only proxy, so Prometheus itself can stay local
PROM = os.environ.get('RACKFAN_PROM', 'http://192.168.1.10:8088/prom/api/v1/query')
# control input: hottest CPU of the hosts in the rack (5-minute average)
QUERY = os.environ.get('RACKFAN_QUERY',
    'max(avg_over_time(node_hwmon_temp_celsius{job=~"pve1|pve2", chip="platform_coretemp_0", sensor="temp1"}[5m]))')
CURVE = [(45, 25), (55, 40), (65, 70), (72, 100)]  # (temperature °C, duty %), linear in between
MIN_DUTY = 25        # never slower than this
FALLBACK = 70        # duty when Prometheus cannot be reached
INTERVAL = 10        # seconds per control loop
STEP_DOWN = 5        # slow down by at most this many % per loop (speeding up is immediate)
TACH_GPIO = 24
PULSES_PER_REV = 2   # Noctua: 2 pulses per revolution
PORT = 9101
PWM_FREQ = 25000     # 25 kHz (Intel/Noctua PWM specification)
PWM_ROOT = '/sys/class/pwm'
# ====================================================

STATE = {'rpm': 0.0, 'duty': 100.0, 'temp': None, 'prom_ok': 0}


class HardwarePWM:
    """Hardware PWM via sysfs (needs dtoverlay=pwm,pin=18,func=2)."""
    def __init__(self):
        chips = sorted(glob.glob(os.path.join(PWM_ROOT, 'pwmchip*')))
        if not chips:
            sys.exit('No PWM controller found. Is "dtoverlay=pwm,pin=18,func=2" in '
                     '/boot/firmware/config.txt and has the Pi been rebooted since?')
        self.chan = os.path.join(chips[0], 'pwm0')
        if not os.path.isdir(self.chan):
            self._w(os.path.join(chips[0], 'export'), '0')
            for _ in range(50):
                if os.path.exists(os.path.join(self.chan, 'period')):
                    break
                time.sleep(0.05)
        self.period = int(round(1e9 / PWM_FREQ))
        try:
            cur = int(open(os.path.join(self.chan, 'duty_cycle')).read().strip() or 0)
            if cur > self.period:
                self._w(os.path.join(self.chan, 'duty_cycle'), '0')
        except (OSError, ValueError):
            pass
        self._w(os.path.join(self.chan, 'period'), str(self.period))
        self.set(100)
        self._w(os.path.join(self.chan, 'enable'), '1')

    @staticmethod
    def _w(path, value):
        with open(path, 'w') as f:
            f.write(value)

    def set(self, pct):
        pct = max(0.0, min(100.0, pct))
        self._w(os.path.join(self.chan, 'duty_cycle'), str(int(self.period * pct / 100)))
        STATE['duty'] = pct


class Tacho:
    """Counts the tachometer pulses on GPIO24 (internal pull-up to 3.3 V)."""
    def __init__(self):
        import lgpio
        self.h = lgpio.gpiochip_open(0)
        lgpio.gpio_claim_alert(self.h, TACH_GPIO, lgpio.FALLING_EDGE, lgpio.SET_PULL_UP)
        try:
            lgpio.gpio_set_debounce_micros(self.h, TACH_GPIO, 200)
        except Exception:
            pass
        self.cb = lgpio.callback(self.h, TACH_GPIO, lgpio.FALLING_EDGE)  # no function = counter only
        self.t = time.monotonic()

    def rpm(self):
        now = time.monotonic()
        n, dt = self.cb.tally(), now - self.t
        self.cb.reset_tally()
        self.t = now
        return n / PULSES_PER_REV / dt * 60 if dt > 0 else 0.0


def curve(t):
    if t is None:
        return FALLBACK
    if t <= CURVE[0][0]:
        return max(MIN_DUTY, CURVE[0][1])
    for (t0, d0), (t1, d1) in zip(CURVE, CURVE[1:]):
        if t <= t1:
            return max(MIN_DUTY, d0 + (d1 - d0) * (t - t0) / (t1 - t0))
    return CURVE[-1][1]


def read_temp():
    try:
        with urllib.request.urlopen(PROM + '?query=' + urllib.parse.quote(QUERY), timeout=5) as r:
            res = json.load(r)['data']['result']
        STATE['prom_ok'] = 1
        return float(res[0]['value'][1]) if res else None
    except Exception as e:
        STATE['prom_ok'] = 0
        print(f'Prometheus not reachable ({e}) - fan set to {FALLBACK} %', flush=True)
        return None


class Metrics(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split('?')[0] != '/metrics':
            self.send_response(404); self.end_headers(); return
        s = STATE
        body = (
            '# HELP rackfan_rpm Rack fan speed\n# TYPE rackfan_rpm gauge\n'
            f'rackfan_rpm {s["rpm"]:.0f}\n'
            '# HELP rackfan_duty_percent Fan duty cycle in percent\n# TYPE rackfan_duty_percent gauge\n'
            f'rackfan_duty_percent {s["duty"]:.0f}\n'
            '# HELP rackfan_input_celsius Control input (hottest CPU temperature, 5-minute average)\n'
            '# TYPE rackfan_input_celsius gauge\n'
            + (f'rackfan_input_celsius {s["temp"]:.1f}\n' if s['temp'] is not None else '')
            + '# HELP rackfan_prometheus_ok 1 if the temperature could be read\n# TYPE rackfan_prometheus_ok gauge\n'
            f'rackfan_prometheus_ok {s["prom_ok"]}\n'
        ).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test(pwm, tacho):
    print('Test: the fan runs each duty cycle for 8 s, then the speed is measured.', flush=True)
    for pct in (100, 70, 40, MIN_DUTY):
        pwm.set(pct)
        time.sleep(3); tacho.rpm(); time.sleep(5)
        print(f'  {pct:3.0f} %  ->  {tacho.rpm():5.0f} rpm', flush=True)
    pwm.set(100)
    print('Done, fan back at 100 %. If the speed rises with the duty cycle, the wiring is correct.')


def main():
    pwm, tacho = HardwarePWM(), Tacho()
    if '--test' in sys.argv:
        return test(pwm, tacho)

    def stop(*_):
        pwm.set(100)  # full cooling when the service stops, to be safe
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    srv = ThreadingHTTPServer(('0.0.0.0', PORT), Metrics)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f'rackfan running, metrics on port {PORT}', flush=True)

    time.sleep(3)  # spin up at 100 %
    tacho.rpm()
    duty = 100.0
    while True:
        t = read_temp()
        STATE['temp'] = t
        want = curve(t)
        duty = want if want >= duty else max(want, duty - STEP_DOWN)
        pwm.set(duty)
        time.sleep(INTERVAL)
        STATE['rpm'] = tacho.rpm()


if __name__ == '__main__':
    main()
