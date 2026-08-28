# Ascon on the World's Smallest Video Game Console
It's [Ascon AEAD-128](https://en.wikipedia.org/wiki/Ascon_(cipher)) running on the [Thumby](https://thumby.us)

Done as a project for my university's cryptography course

Note that **this code is NOT production ready**, you should probably just be using [the implementation by the original authors](https://github.com/ascon/ascon-c)

See the [included pdf](Ascon%20on%20the%20World%27s%20Smallest%20Video%20Game%20Console.pdf) for more details on how the cipher works and how I created/tested this project

# Building

## ThumbyPowerConsumption

Here's where all the Thumby code lives

To set up your environment:
1. Download/Install the [Arduino IDE](https://www.arduino.cc/en/software)
2. Download the [Thumby Graphics Library](https://github.com/TinyCircuits/TinyCircuits-GraphicsBuffer-Lib/archive/refs/heads/master.zip) and the [Core Thumby Library](https://github.com/TinyCircuits/TinyCircuits-Thumby-Lib/archive/refs/heads/master.zip) as zip files
3. Add them to the Arduino IDE by going to `Sketch` -> `Include Library` -> `Add .ZIP Library...`
4. Install [version 2.2.2 of arduino-pico](https://github.com/earlephilhower/arduino-pico/releases/tag/2.2.2)
    1. Go to `File` -> `Preferences` and paste `https://github.com/earlephilhower/arduino-pico/releases/download/global/package_rp2040_index.json` into the `Additional boards manager URLs` section
    2. In the `Boards Manager` tab there should now be a new entry called `Raspberry Pi Pico/RP2040`
    3. Change the version to `2.2.2` and click `Install`
    - Alternatively: experiment with versions until you find a newer one that actually works with the Thumby (this may require making a PR to one or more of the Thumby libraries you downloaded earlier)
5. Now you should be safe to open the included [`.ino`](ThumbyPowerConsumption/ThumbyPowerConsumption.ino) file and have everything compile correctly
6. Follow the [uploading instructions](https://thumby.us/CCPP/Uploading-Sketches) from TinyCircuits to actually upload the code to the Thumby
    - Just skip steps 1 and 2 under the `Uploading` heading... you should already have the IDE open to this very project!

## AsconTests

This lets you run my Ascon implementation locally for easier correctness testing

It should just be a regular Visual Studio (2022) C++ project, so open the [`.sln`](ThumbyPowerConsumption/AsconTests/AsconTests.sln) file and hit compile

The [`ref`](ThumbyPowerConsumption/AsconTests/ref) folder contains [the reference implementation](https://github.com/ascon/ascon-c/tree/main/crypto_aead/asconaead128/ref) that my implementation is being compared against

# Licensing
The [included pdf](Ascon%20on%20the%20World%27s%20Smallest%20Video%20Game%20Console.pdf) is licensed under [CC BY 4.0 International](https://creativecommons.org/licenses/by/4.0/deed.en)

The [Ascon reference implementation](ThumbyPowerConsumption/AsconTests/ref) is licensed under [CC0 1.0 Universal](https://github.com/ascon/ascon-c/blob/main/LICENSE)

The rest of the repo is licensed under [MIT](LICENSE.txt)