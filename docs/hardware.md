# Hardware

Nothing here is required except a screen and something that runs a browser. This is the setup the
dashboard was built for.

| Part | Example | Notes |
|---|---|---|
| Rack | 10-inch mini rack | any rack with a free 2U slot for the display |
| Display | GeeekPi/DeskPi **DP-0059**, 7.84″, 1280×400, capacitive touch, 2U | the layout is made for 1280×400; other sizes are scaled |
| Computer for the display | **Raspberry Pi 4B** | a Pi 5 should run the panel; the fan script is untested there |
| Fan (optional) | **Noctua NF-A12x25 5V PWM** (120 mm, 5 V) | the 5 V version can be powered from the Pi; do **not** use a 12 V fan on the 5 V pin |
| Network | cable to a switch port | Wi-Fi works but cable is more reliable |

## Fan wiring

The fan connects directly to the Pi's GPIO header with female jumper wires – no soldering, no extra
board. Use the outer pin row:

| Pi pin | Signal | Noctua wire (4-pin) |
|---|---|---|
| 4 | 5 V | yellow |
| 6 | GND | black |
| 12 | GPIO18 – PWM (25 kHz hardware PWM) | blue |
| 18 | GPIO24 – tachometer (internal pull-up) | green |

```
            3V3  (1) (2)  5V
          GPIO2  (3) (4)  5V      ← yellow (+5 V)
          GPIO3  (5) (6)  GND     ← black
          GPIO4  (7) (8)  GPIO14
            GND  (9) (10) GPIO15
         GPIO17 (11) (12) GPIO18  ← blue (PWM)
         GPIO27 (13) (14) GND
         GPIO22 (15) (16) GPIO23
            3V3 (17) (18) GPIO24  ← green (tacho)
```

Notes:

- The tachometer is an open-collector output; the Pi's internal pull-up to 3.3 V is enough, no
  resistor needed.
- A single 5 V Noctua fan is a small load for the Pi's 5 V rail; check your fan's data sheet if you
  add more.
- `rackfan.py` is tested on a Pi 4 only. On a Pi 5 the PWM setup differs.
- The script never goes below 25 % duty (`MIN_DUTY`).

## Power and placement

- Use a good power supply (the official one for your Pi model), especially with the fan attached.
- Mount the fan at the top of the rack blowing upwards/outwards – the controller follows the
  hottest server CPU, not the Pi.
