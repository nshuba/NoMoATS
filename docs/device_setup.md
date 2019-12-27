## Preparing your Android Device

These instructions are provided to replicate the setup we used in the
AutoLabel paper. We used a **Nexus 6** device with **Android 7.1**. How to
mimic the Android 7.1 installation that we performed and our rooting
process is explained below.

### Prerequisites
* Android Development Tools:
  ```
  $ sudo apt-get install android-tools-adb android-tools-fastboot
  ```

### Preparing the OS
#### Flashing Android 7.1
First, allow OEM unlocking:
* Go to Settings --> About Phone
* Click the Build Number 7 times
* Go back to Settings --> Developer Options and enable "OEM Unlocking"
* While in Developer Options, ensure the USB Debugging box is checked

Flashing:
* Download the Android 7.1.1 (N6F27M, Oct 2017) image from
[Google](https://developers.google.com/android/images#shamu).
* Unzip it and also unzip the `image-shamu-n6f27m` file within.
* Enter the bootloader mode on your device. You can do this in 2 ways:
    * Turn off the device and then turn it on by pressing both the power
    button and the volume down button
    * Executing the following from a connected computer: `adb reboot bootloader`
* While in bootloader mode, we recommend pressing the volume up key until
you are in "Bootloader Logs." This will help you see what the device is doing
while we are flashing.
* Connect the device to your computer
* Open a terminal and navigate to the unzipped `image-shamu-n6f27m`
directory.
* Execute the following commands in the terminal (note that flashing the
system.img sometimes takes over 5 minutes):
    ```
    $ fastboot flash system system.img
    $ fastboot flash boot boot.img
    $ fastboot flash recovery recovery.img
    $ fastboot flash cache cache.img
    $ fastboot flash userdata userdata.img
    $ fastboot reboot
    ```

The device will boot and you are ready for the next section.

#### Setting up the Device
* Once the device boots, you will be asked to setup it. Setup it up as
you see fit, but **do not provide a Wi-Fi network**. The device must remain
disconnected from the Internet until we turn off auto-updating.
* When you are finished setting up the device and are taken to the home
screen, go to Settings and enable Developer options again.
* Go to Settings --> Developer Options and disable "Automatic System Updates."
* While in Developer Options, ensure the USB Debugging box is checked
* Now you can connect your device to a Wi-Fi network. The device may start
updating certain apps. As long as WebView and Google Play Service do not
update, we should be ok. **Note**: you can cancel updates by expanding the
notification.
* Open the Google Play Store app and sign into your Google account. From
the app, expand the hamburger menu and go to Settings. Click on
"Auto-update apps" and select "Don't auto-update apps."
* Now we need to enable the Android System WebView. Go to Settings --> Apps
and find Chrome. Click on it and then click "Disable."
* Go back one screen to see the full list of apps. To make sure we have the
correct setup, click on the top right menu and click "Show system."
* Find the Android System WebView app, make sure it is enabled, and
make sure it's version is 55.0.2883.91. Then find Google Play Services
and make sure it's version is 9.8.79.
  * If the apps ended up updating, don't worry. You can click on the top right
  menu within each app and click "Uninstall updates."

### Rooting
Instructions below are adapted this XDA Developers
[forum thread](https://forum.xda-developers.com/nexus-6/general/how-to-nexus-6-one-beginners-guide-t2948481).

* Download the CF Auto-Root for Nexus 6 from this
[link](http://download.chainfire.eu/628/CF-Root/CF-Auto-Root/CF-Auto-Root-shamu-shamu-nexus6.zip)
* Extract the ZIP file
* Boot your device into bootloader (as we did in
[Flashing Android 7.1](#flashing-android-71))
* Connect your device to your computer
* Open a terminal, navgiate to the unzipped CF Auto-Root directory, and
execute the following:
    ```
    $ fastboot boot image\CF-Auto-Root-shamu-shamu-nexus6.img
    ```

Don't interrupt the process until the device finishes booting. When it's
done you can check that you have obtained root by executing:
```
$ adb shell
shamu:/ $ su
shamu:/ #
```

Note that the SU binary on the device will ask you to grant permission to
the shell script before the `su` command succeeds. Your device is now
rooted and you can start using AutoLabel!