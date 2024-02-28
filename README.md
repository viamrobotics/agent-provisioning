# Agent Provisioning
This is a subsystem (plugin) for the viam-agent that provides network (wifi) management and headless provisioning services.

## Installation
This will be automatically installed for online devices (robots) that are using the agent. See install instructions at https://github.com/viamrobotics/agent

It should work "out of the box" on Debian Bookworm or newer. For Bullseye, it's neccessary to switch the network configuration to using NetworkManager first. `sudo raspi-config` and then navigate `Advanced Options`>`Network Config`>`NetworkManager` Note that this is automatically handled for new installs using the main agent's install.sh script.


## Offline/pre-installation
NOTE: This is for preinstallation on images/sd cards. If you have a live system, use the main agent installer linked at the top of this page.

### Short version (For Raspberry Pi)
Flash a 64-bit image to your SD card using the Raspberry Pi Imager, and customize at least the hostname when prompted. Eject and reinsert the card to make sure it's mounted with the newly written contents. Then simply run the following script.

```
sudo /bin/sh -c "$(curl -fsSL https://storage.googleapis.com/packages.viam.com/apps/viam-agent/preinstall.sh)"
```

## Preinstall Details
We provide a preinstall script that can auto-detect some common (Raspberry Pi ands similar) mounted images, but it can also be used to locally generate a tarball package you can extract yourself or you can manually specify the image root (if it's not a mountpoint of its own.) Please note this script works only under POSIX (MacOS and Linux) at the moment. If you make use of this, you may want to also look at [Factory/Manufacturer Configuration](#factorymanufacturer-configuration) below as well.

[Download from here](https://storage.googleapis.com/packages.viam.com/apps/viam-agent/preinstall.sh) and make the script executable `chmod 755 preinstall.sh`

Running it without options `sudo ./preinstall.sh` will attempt to auto-detect a mounted root filesystem (or for Raspberry Pi, bootfs) and also automatically determine the architecture.

If you want to just create a tarball you can extract on your own, use one of the following:

`sudo ./preinstall.sh --aarch64` for an arm64 package
OR
`sudo ./preinstall.sh --x86_64` for an amd64 package

Lastly, if the script cannot detect your mountpoint, you can specify it directly. Ex: `sudo ./preinstall.sh /path/to/rootfs`

### Manual install
1. Create directories `/opt/viam/bin/` and  `/opt/viam/tmp`
1. Download/copy the viam-agent and viam-agent-provisioning binaries into `/opt/viam/tmp`
1. Make sure they are marked as executable (if downloaded from the web) `chmod 755 /opt/viam/tmp/viam-agent*`
1. Symlink the agent binary to `bin/viam-agent`
    * Note: On this and subsequent symlink operations, be sure to use relative symlinks, especially if working on a mounted image or otherwise non-live system
1. Symlink the provisioning binary to `bin/agent-provisioning`
1. Copy the systemd [service file](https://github.com/viamrobotics/agent/blob/main/subsystems/viamagent/viam-agent.service) from the agent repo to `/etc/systemd/system/viam-agent.service`
1. Symlink the service file to /etc/systemd/system/multi-user.target.wants/viam-agent.service
1. Make sure NetworkManager is installed and enabled in systemd
1. (Optional) Install a factory provisioning configuration file to `/etc/viam-provisioning.json` as detailed below

Note: On all symlink operations, be sure to use relative symlinks, especially if working on a mounted image (e.g. not a live/booted system.)


#### Factory/Manufacturer Configuration
`/etc/viam-provisioning.json` can be placed on a device image to customize the provisioning experience. 

Example `/etc/viam-provisioning.json`
```json
{
  "manufacturer": "Skywalker",
  "model": "C-3PO",
  "fragment_id": "2567c87d-7aef-41bc-b82c-d363f9874663",
  "disable_dns_redirect": true,
  "hotspot_prefix": "skywalker-setup",
  "hotspot_password": "skywalker123"
}
```
* All fields are optional (as is the entire file.) Values not set will use defaults.
* manufacturer: defaults to `viam`
  * Purely informative. May be displayed on captive portal and/or mobile app.
* model: defaults to `custom` 
  * Purely informative. May be displayed on captive portal and/or mobile app.
* fragment_id: No default.
  * Corresponds to a fragment_id in the Viam cloud. If present, mobile app can pre-configure a robot for a user by using this.
* disable_dns_redirect: Defaults to false.
  * By default, ALL DNS lookups via the provisioning hotspot will redirect to the device. This causes most phones/mobile devices to automatically redirect the user to the captive portal as a "sign in" screen.
  * When disabled, only domains ending in `.setup` (ex: `viam.setup`) will be redirected. This generally avoids displaying the portal to users and is mainly used in conjunction with a mobile provisioning application workflow.
* hotspot_prefix: Defaults to `viam-setup`
  * Will have the hostname of the device append and be used for the provisioning hotspot SSID.
* hotspot_password: Defaults to `viamsetup`
  * Wifi password for provisioning hotspot.

## Mobile App Provisioning
If you are using the Viam mobile app, and your device has been pre-installed with the agent (per above steps) you can use the mobile app to configure your robot, instead of the captive web portal. 

### Steps in Viam mobile app
Download the Viam mobile app from [Apple App Store](https://apps.apple.com/vn/app/viam-robotics/id6451424162) or [Google Play](https://play.google.com/store/apps/details?id=com.viam.viammobile&hl=en&gl=US).

Within the [Viam mobile app](https://docs.viam.com/fleet/#the-viam-mobile-app) once logged in, navigate to an organization, then to a location, then inside any location tap "Add new smart machine", and follow the instructions in app. See the mobile app documentation for further details.

## User Configuration
No configuration is neccessary for normal end-user use. Provisioning mode will start a hotspot when either not configured (no /etc/viam.json) or not online.

### Additional Networks (Optional)
To add additional networks to an already-online device, go to the "Raw JSON" button on the Config tab for your robot/device in https://app.viam.com

From there, add an `attributes` field to the agent-provisioning subsystem, using the example below.

```json
"agent_config": {
    "subsystems": {
      "agent-provisioning": {
        "release_channel": "stable",
        "pin_version": "",
        "pin_url": "",
        "disable_subsystem": false,
        "attributes": {
          "hotspot_password": "testpass",
          "networks": [
            {
              "type": "wifi",
              "ssid": "primaryNet",
              "psk": "myFirstPassword",
              "priority": 30
            },
            {
              "type": "wifi",
              "ssid": "fallbackNet",
              "psk": "mySecondPassword",
              "priority": 10
            }
          ]
        }
      },
```
Note: the `hotspot_password` overrides the default password (either the default `viamsetup` or any factory-customized password) used to connect to the hotspot if you wish to further secure things. It is optional and can be omitted entirely.

## Use
Provisioning mode will start a hotspot when either not configured (no /etc/viam.json) or not online. By default, the wifi SSID will be `viam-setup-$HOSTNAME`. The default password is `viamsetup`. After connecting with a mobile device, you should be redirected to a sign-in page. If you are using a laptop or are not redirected, try opening http://viam.setup/ in a browswer. From the portal page, you can select an SSID and provide a password to allow your device to connect. The setup hotspot will disappear (and disconnect your mobile device) while the device attempts connection. If the hotspot reappears, there may be have been an issue or invalid password. Please try again.

### Pre-installed provisioning
If there is no `/etc/viam.json` present, the captive portal will also require you to paste the content of the viam-server config to use in `/etc/viam.json` This can be copied from the "Setup" tab of your machine in https://app.viam.com by clicking the "Copy viam-server configuration" button near the top right.

### Test CLI Utility
There is a simple CLI client available to test the GRPC components of the provisioning service. Run `go run ./cmd/client/` for info.
