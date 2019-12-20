# NoMoATS
This is the main repository for NoMoATS - a system that automatically explores Android apps,
collects network traces, and labels the collected network requests with the advertising/tracking (A&T) 
libraries responsible for generating them. For a deeper overview of the project, please visit the
project [website](http://athinagroup.eng.uci.edu/projects/nomoads/).

NoMoATS consists of several components that are split among several GitHub repositories.
You can use these components together, or in isolation, depending on 
whether or not you want to collect your own data. Use the guide below to help you select where to start:

* If you just want to use the NoMoATS dataset and apply our machine learning (ML) approach,
go directly to our ML repo - [NoMoAds](https://github.com/nshuba/nomoads).
* If you have some APK files (Android apps) for which you want to collect network traffic and have it
labeled, go to the [Running NoMoATS](#running-nomoats) section.
    - **Note:** *this component requires a rooted Android device.*
* If you need to download APK files, you are welcome to use our download scripts, located in our
[download_apks repo](https://github.com/nshuba/download_apks).
Then, start at the [Running NoMoATS](#running-nomoats) section.
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

## Running NoMoATS
**Note**: *the documentation that follows is still a work-in-progress.*

The NoMoATS system in this repository is further split among two main components:

* [Capturing Network Traffic with Stack Traces](#capturing-network-traffic-with-stack-traces)
* [Labeling Captured Network Traces](#labeling-captured-network-traces)

For the rest of the document we will refer to the directory to which you have cloned the NoMoATS
repo as `<AUTO_LABEL_ROOT>`.

NoMoATS provides a script to automate both components. Once you have your APK files,
complete the prerequisites in Sections 2 and 3, and then simply
use the `<AUTO_LABEL_ROOT>/data_collection/driver.py` script to
explore apps, capture traces, and label them. Documentation for this
script is available via:
```
$ cd <AUTO_LABEL_ROOT>/scripts/data_prep/
$ python2.7 driver.py -h
```

**Operating System Requirement**: NoMoATS has been tested on Ubuntu 18, but it's possible that it
may work on other operating systems.

### Capturing Network Traffic with Stack Traces
#### Prerequisites
##### Preparing your Ubuntu Environment
* Python 2.7
* Android Development Tools:
  ```
  $ sudo apt-get install android-tools-adb android-tools-fastboot
  ```

* Download [DroidBot](https://github.com/honeynet/droidbot)
  ```
  $ git clone https://github.com/honeynet/droidbot.git
  ```

* We will refer to the DroidBot directory to which you cloned as `<DROIDBOT>`.
Now apply the NoMoATS patch, and install DroidBot, which will also install
Frida. *Note*: you may want to run `pip install` with `sudo`.
  ```
  $ cd <DROIDBOT>
  $ git checkout 8706b9dd6226bed5dc89ff8a6fcbcff952be3c2e
  $ patch -p1 < <AUTO_LABEL_ROOT>/auto_label_patch.diff
  $ pip install -e .
  ```

* To make sure that DroidBot and Frida installed correctly, try running the
following:
    ```
    $ droidbot -h
    $ frida -h
    ```

* Now we need to install Node.JS and use it to compile our Frida scripts.
First, change to a directory where you want to keep your Node.JS modules.
For example, your home directory. We will refer to this directory as
`<NODE_HOME>`.
  ```
  $ cd <NODE_HOME>
  $ sudo apt-get install npm
  $ sudo npm install -g n
  $ sudo n stable
  $ sudo npm install frida-compile@8.0.1
  $ sudo npm install frida-java@2.0.8
  $ cd <DROIDBOT>/droidbot/packet_capture/
  $ <NODE_HOME>/node_modules/.bin/frida-compile java_hooks.js -o frida_agent.js
  ```

That's it!

#### Preparing your Android Device
Frida also requires a few more steps to prepare your device:
* First, root your device. Instructions vary based on device type.
[CF-Auto-Root](https://desktop.firmware.mobi/) can be used to root most
 devices.
  * **If you would like to fully replicate our setup**: see instructions in
  [device_setup.md](docs/device_setup.md) in the `<AUTO_LABEL_ROOT>/docs/`
  directory.
* Currently, we do not support IPv6, so if you are on a network that supports
 IPv6, we recommend disabling it on your mobile device. Disabling lasts only
 until your device reboots or joins another network. For convenience, we
 packaged two scritps for enabling and disabling IPv6. Push them to your
 device so you can run them each time you want to capture traffic:
     ```
     $ adb push <AUTO_LABEL_ROOT>/scripts/device_prep/disable_ipv6.sh /data/local/tmp
     $ adb push <AUTO_LABEL_ROOT>/scripts/device_prep/enable_ipv6.sh /data/local/tmp
     $ adb shell
     shell@shamu:/ $ cd /data/local/tmp
     shell@shamu:/data/local/tmp $ su
     root@shamu:/data/local/tmp # chmod 755 disable_ipv6.sh
     root@shamu:/data/local/tmp # chmod 755 enable_ipv6.sh
     ```
* Now download the Frida server corresponding to the version we installed:
   ```
   $ wget https://github.com/frida/frida/releases/download/12.2.26/frida-server-12.2.26-android-arm.xz
   ```
* Extract the contents and then push to your Android device:
   ```
   $ adb push frida-server-12.2.26-android-arm /data/local/tmp
   $ adb shell
   shell@shamu:/ $ cd /data/local/tmp
   shell@shamu:/data/local/tmp $ su
   root@shamu:/data/local/tmp # mv frida-server-12.2.26-android-arm frida-server
   root@shamu:/data/local/tmp # chmod 755 frida-server
   root@shamu:/data/local/tmp # ./frida-server &
   ```
* The console won't print anything, so just let it be. To check if everything
installed correctly, pick an application package name that exists on your
device (e.g. `com.android.browser`) and type the following:
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

#### Running
* First, disable IPv6 (if you are on a network that supports it):
    ```
   $ adb shell
   shell@shamu:/ $ cd /data/local/tmp
   shell@shamu:/data/local/tmp $ su
   root@shamu:/data/local/tmp # ./disable_ipv6.sh
    ```
* We integrated the capture with [DroidBot](https://github.com/honeynet/droidbot),
  so all you have to do now is run Droidbot as usual:
    ```
    droidbot -a <PATH_TO_APK> -o output_dir
    ```

Note that in our experiments we ran DroidBot with more tuned parameters.
See `<AUTO_LABEL_ROOT>/scripts/data_prep/driver.py` for the exact parameters.
And use the `droibot -h` command to learn more.

### Labeling Captured Network Traces
#### Prerequisites
##### LibRadar
There are two versions of LibRadar that you can use:
* [LibRadar](https://github.com/pkumza/LiteRadar)
* [LibRadar++](http://market.orangeapk.com/) - an updated version of LibRadar. At the time of
writing, it is not available on GitHub, but you can email the author to get the code.
Note that LibRadar++ requires Python 3.7

Download either version of LibRadar and follow any other steps required for setup by each tool.
Mark the location of the main Python script. At the time of
writing, these scripts were at the following locations:
* LibRadar: `LiteRadar/literadar.py`
* LibRadar++: `libradar/main.py`

For the rest of the document, we will refer to either of those scripts as `<libradar.py>`

##### Others
* Tshark:
  ```
  $ sudo apt-get install tshark
  ```
* A mapping of package names to library type. Currently, we are using
the one provided by LibRadar. Download it from
[here](https://github.com/pkumza/LiteRadar/blob/master/LiteRadar/Data/tag_rules.csv).
We will refer to this file as `<tag_rules.csv>` for the rest of the document.

#### Running
In this Section we assume that you already have some data captured
(e.g. from [Section 2](#2-capturing-network-traffic-with-stack-traces))
for a particular app. We also assume that you have that app's APK.

1. Analyze the APK with LibRadar, and save the output. For example,
with LibRadar++:
    ```
    $ python3.7 <libradar.py> <PATH_TO_APK> > <libradar_output.txt>
    ```

2. If part of the network traces are in PCAPNG format, convert them to JSON:
    ```
    $ cd <AUTO_LABEL_ROOT>/scripts/data_prep/
    $ python2.7 pcap_to_json.py <pcap_path>
    ```
The above command will save a file in the same directory is the PCAPNG file,
and will name it `tshark.json`.

3. Now use the output file to match against stack traces in captured traffic:
    ```
    $ cd <AUTO_LABEL_ROOT>/scripts/data_prep/
    $ python2.7 extract_from_tshark.py <tshark_path> <webview_path> <libradar_output.txt> <tag_rules.csv> <output.json>
    ```
The arguments in the above command stand for the following:
* `<tshark_path>` - path to `tshark.json` from step 2
* `<webview_path>` - path to WebView traffic captured (e.g. from [Section 2](#2-capturing-network-traffic-with-stack-traces))
* `<libradar_output.txt>` - path to `<libradar_output.txt>` from step 1
* `<tag_rules.csv>` - mapping of package names to library type
* `<output.json>` - output file to which to save labeled data to

## Acknowledgements
* [Frida](https://www.frida.re/)
* [LibRadar](https://github.com/pkumza/LiteRadar)
* [LibRadar++](http://market.orangeapk.com/)
* [DroidBot](https://github.com/honeynet/droidbot)