# NoMoATS
This is the main repository for NoMoATS - a system that automatically explores Android apps,
collects network traces and the stack traces that led to each request. Using stack trace analysis,
NoMoATS labels the collected network requests with the advertising/tracking (A&T) 
libraries responsible for generating them. For a deeper overview of the project, please visit the
project [website](http://athinagroup.eng.uci.edu/projects/nomoads/).

NoMoATS consists of several components that are split among several GitHub repositories.
You can use these components together, or in isolation, depending on 
whether or not you want to collect your own data. Use the guide below to help you select where to start:

* If you just want to use the NoMoATS dataset and apply our machine learning (ML) approach,
go directly to our ML repo - [NoMoAds](https://github.com/nshuba/nomoads).
The [NoMoAds](https://github.com/nshuba/nomoads) repo also offers a VM for a quick start.
* For a **quick start** with NoMoATS, we provide a VM which has all the prerequisites installed. Go to
the [Quick Start with a VM](#quick-start-with-the-provided-vm) section for instructions on how to use our VM.
* If you have some APK files (Android apps) for which you want to collect network traffic and have it
labeled, then start at the [Prerequisites](#prerequisites) section and continue to the [Running NoMoATS](#running-nomoats) section.
    - **Note:** *this component requires a rooted Android device.*
* If you need to download APK files, you are welcome to use our download scripts, located in our
[download_apks repo](https://github.com/nshuba/download_apks).
Then, start at the [Prerequisites](#prerequisites) section and continue to the [Running NoMoATS](#running-nomoats) section.
    - **Note:** *this component requires a Google Play account.*
    
## Citing NoMoATS
If you create a publication (including web pages, papers published by a
third party, and publicly available presentations) using NoMoATS or the
NoMoATS dataset, please cite the
corresponding paper
as follows:

```
@article{shuba2020nomoats,
  title={{NoMoATS: Towards Automatic Detection of Mobile Tracking}},
  author={Shuba, Anastasia and Markopoulou, Athina},
  journal={Proceedings on Privacy Enhancing Technologies},
  volume={2020},
  number={2},
  year={2020},
  publisher={De Gruyter Open}
}
```

We also encourage you to provide us (<nomoads.uci@gmail.com>) with a
link to your publication. We use this information in reports to our
funding agencies.

## Quick Start with the Provided VM
* Download our Ubuntu 18.04 VMWare image from [here](https://drive.google.com/file/d/1txXOo1KiJ5dpOA9ukDFvVeCQ-d1rX9sl/).
The image has all the prerequisites installed, an Android emulator, and a sample APK to get you started in no time.
    * **Note**: the image should also work with Virtual Box if you create a new VM within Virtual Box and pick
    "use existing disk".
    * **Note on the RAM**: the image comes with the RAM set to 8GB. This is needed to run the Android emulator smoothly.
If your host machine cannot spare 8GB of RAM, you can decrease the VM's RAM and use an Android device instead of an
emulator - see Section [Emulator vs. Real Android Device](#emulator-vs-real-android-device) below.
* Power on the image. Password is `nomoats`
* First, we will start the Android emulator. Open a terminal and type the following:
  ```
  $ cd ~/android-sdk/tools/
  $ ./emulator -avd Nexus6_API25
  ```
* Wait for the emulator to start up. When it's ready, open another terminal window and type the following:
  ```
   $ adb shell
   generic_x86:/ # cd /data/local/tmp
   generic_x86:/data/local/tmp # ./frida-server &
  ```
* Now we are ready to run NoMoATS. Type the following in another terminal window:
  ```
  $ cd ~/NoMoATS/data_collection/
  $ python driver.py ~/test/apks/ ~/LiteRadar/LiteRadar/literadar.py -e
  ```
* Be patient as the APK is analyzed and installed. After that it will be automatically exercised for
five minutes. When the script finishes, skip to the [NoMoATS Output](#nomoats-output) section for
instructions on how to view the results, which are saved to the `/home/nomoats/test` directory on the VM.

### Emulator vs. Real Android Device
You can also use our VM with your own Android device, instead of the emulator. See the 
[Preparing your Android Device](#preparing-your-android-device) section for instruction on how to
replicate our Android setup. If using your own device, beware of the following:
* You may need to run `su` after the `adb shell` command to gain root privilege, which is required
    for running the Frida server
* Omit the `-e` option when invoking the `driver.py` script

Using a real device is recommended since **the emulator has the following limitations**:
* Currently, we don't have a script for disabling IPv6 traffic, which is currently not supported by NoMoATS.
* Currently, we could not find a way to downgrade Google Play services, which breaks how we get the stack trace
    in certain WebViews.
* The emulator does not send a process crash signal to Frida, which hinders NoMoATS' ability to restart apps upon a crash


## Prerequisites
**Operating System Requirement**: NoMoATS has been tested on Ubuntu 18, but it's possible that it
may work on other operating systems.

### Preparing your Ubuntu Environment
NoMoATS relies on various standard [Ubuntu packages](#ubuntu-packages) and two other research projects -
[LibRadar](#libradar) and [Droidbot](#droidbot), as described in the following sub-sections.
#### Ubuntu Packages
* Python 2.7 and pip:
  ```
  $ sudo apt-get install python
  $ sudo apt-get install python-pip
  ```
* Tshark:
  ```
  $ sudo apt-get install tshark
  ```
* Android Development Tools:
  ```
  $ sudo apt-get install android-tools-adb
  ```
* At this point you ready to install NoMoATS, which will pull down other requirements, including
[Frida](https://www.frida.re/):
  ```
  $ git clone https://github.com/nshuba/NoMoATS.git
  $ cd NoMoATS
  $ pip install -e .
  ```
* To make sure that Frida installed correctly, try running the following:
    ```
    $ frida -h
    ```
#### LibRadar
* Download [LibRadar](https://github.com/pkumza/LiteRadar) and its database:
    ```
    $ git clone https://github.com/pkumza/LiteRadar.git
    $ cd LiteRadar/LiteRadar/Data
    $ wget https://github.com/pkumza/Data_for_LibRadar/raw/master/lite_dataset_10.csv
    ```
* Make a note of the `LiteRadar/LiteRadar/literadar.py` file location in the downloaded repo. 
We will refer to it as as `<libradar.py>`
* Note that in our paper we used [LibRadar++](https://eprints.networks.imdea.org/1885/1/imc18-final148.pdf) -
an updated version of LibRadar. 
    * At the time of writing, the code is not publicly available, but you can email the author to get it.
    * If you use LibRadar++, the `<libradar.py>` script that we refer to in later sections is located in `libradar/main.py`

#### Droidbot
* To automatically explore apps, we use the [DroidBot](https://github.com/honeynet/droidbot) tool,
with some modifications. You can setup our modified version of DroidBot as follows:
  ```
  $ git clone https://github.com/nshuba/droidbot
  $ cd droidbot
  $ git checkout nomoats
  $ pip install -e .
  ```

* To make sure that DroidBot installed correctly, try running the following:
    ```
    $ droidbot -h
    ```

That's it!

### Preparing your Android Device
Frida also requires a few more steps to prepare your device:
* First, root your device. Instructions vary based on device type.
[CF-Auto-Root](https://desktop.firmware.mobi/) can be used to root most
 devices.
* Although you can use any device and Android version, for best results **we strongly recommend you fully replicate our 
setup**: by following the instructions provided in
  [device_setup.md](docs/device_setup.md) in the `NoMoATS/docs/`
  directory. Otherwise, Frida may have issues fetching stack traces in certain cases.
* Currently, we do not support IPv6, so if you are on a network that supports
 IPv6, we recommend disabling it on your mobile device. Disabling lasts only
 until your device reboots or joins another network. For convenience, we
 packaged two scripts for enabling and disabling IPv6. Push them to your
 device so you can run them each time you want to capture traffic:
     ```
     $ adb push NoMoATS/scripts/device_prep/disable_ipv6.sh /data/local/tmp
     $ adb push NoMoATS/scripts/device_prep/enable_ipv6.sh /data/local/tmp
     $ adb shell
     shell@shamu:/ $ cd /data/local/tmp
     shell@shamu:/data/local/tmp $ su
     root@shamu:/data/local/tmp # chmod 755 disable_ipv6.sh
     root@shamu:/data/local/tmp # chmod 755 enable_ipv6.sh
     ```
* NoMoATS uses Frida version 12.2.6, so you have to download the corresponding Frida server for your device
from [here](https://github.com/frida/frida/releases/tag/12.2.6). For example, if you are using
an ARM device, you can download the corresponding Frida server as follows:
   ```
   $ wget https://github.com/frida/frida/releases/download/12.2.26/frida-server-12.2.26-android-arm.xz
   ```
* Extract the contents and then push to your Android device:
   ```
   $ xz --decompress frida-server-12.2.26-android-arm.xz
   $ adb push frida-server-12.2.26-android-arm /data/local/tmp/frida-server
   $ adb shell
   shell@shamu:/ $ cd /data/local/tmp
   shell@shamu:/data/local/tmp $ su
   root@shamu:/data/local/tmp # chmod 755 frida-server
   root@shamu:/data/local/tmp # ./frida-server &
   ```
* To test if everything installed correctly you can do the following:
    * First, on your device, start the Frida server:
       ```
       $ adb shell
       shell@shamu:/ $ cd /data/local/tmp
       shell@shamu:/data/local/tmp $ su
       root@shamu:/data/local/tmp # ./frida-server &
       ```
    * Next, pick an application package name that exists on your device (e.g. `com.android.browser`) 
    and execute the following on your host machine:
        ```
        $ frida -U com.android.browser
        frida -U com.android.browser
             ____
            / _  |   Frida 10.7.7 - A world-class dynamic instrumentation toolkit
           | (_| |
            > _  |   Commands:
           /_/ |_|       help      -> Displays the help system
           . . . .       object?   -> Display information about 'object'
           . . . .       exit/quit -> Exit
           . . . .
           . . . .   More info at http://www.frida.re/docs/home/
    
        [Android Emulator 5554::com.android.browser]->
        ```
If you see output similar to above, then your device is ready!

## Running NoMoATS
* Prepare an APK (or multiple APKs) that you want to test and place them in a folder.
* Disable IPv6 on your Android device (if you are on a network that supports it) and
then start the Frida server:
    ```
   $ adb shell
   shell@shamu:/ $ cd /data/local/tmp
   shell@shamu:/data/local/tmp $ su
   root@shamu:/data/local/tmp # ./disable_ipv6.sh
   root@shamu:/data/local/tmp # ./frida-server &
    ```
* Now run the NoMoATS driver script:
    ```
    $ cd NoMoATS/data_collection/
    $ python2.7 driver.py <apks_dir> <libradar.py> tag_rules.csv
    ```
  * `<apks_dir>`: the directory containing your APK files
  * `<libradar.py>`: the main LibRadar script (see [Section LibRadar](#libradar))
  * `tag_rules.csv`: a mapping of package names to library type. Currently, we are using
the one provided by LibRadar. We downloaded it from
[here](https://github.com/pkumza/LiteRadar/blob/master/LiteRadar/Data/tag_rules.csv) and included it
in our repo. You can replace this file with newer versions as they become available.
   
### NoMoATS Output
The `driver.py` script first runs LibRadar on the provided APK(s) and then runs Droidbot (along with
our Frida scripts that capture traffic). 
Next, the script extracts and labels the collected data and saves it in a friendly JSON format.
When it's done, your directory structure will look similar to this:
  ```
  --> apks/
        --> app1.apk
        --> app2.apk
        --> ...
  --> libradar_output/
        --> app1.txt    (a list of third-party package names found by LibRadar in the app)
        --> ...other apps...
  --> nomoats_output/
        --> app1/
            --> app1.pcapng         (captured network traffic)
            --> tshark.json         (the PCAPNG file converted to JSON via tshark)
            --> webview_loads.json  (traffic captured from WebView components)
            --> nativelibs.json     (list of any native libraries that were loaded by the app)
            --> ...other DroidBot-specific output...
        --> ...other apps...
  --> extracted_data/
        --> app1.json   (captured and labeled traffic, including WebView traffic)  
        --> ...other apps...     
  ```
You can use the files in the `extracted_data` folder to train ML classifiers
using our ML repo - [NoMoAds](https://github.com/nshuba/nomoads). NoMoAds also contains various
scripts that can help you further analyze the captured data.

## Acknowledgements
* [Frida](https://www.frida.re/)
* [LibRadar](https://github.com/pkumza/LiteRadar)
* [LibRadar++](https://eprints.networks.imdea.org/1885/1/imc18-final148.pdf)
* [DroidBot](https://github.com/honeynet/droidbot)