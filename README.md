# Agent Provisioning
This is a subsystem (plugin) for the viam-agent that provides network (wifi) management and headless provisioning services.

## WIP
This is a work in progress projects changing rapidly. More features will be coming soon.

## Installation
This will be automatically installed for online devices (robots) that are using the agent. See install instructions at https://github.com/viamrobotics/agent

It should work "out of the box" on Debian Bookworm or newer. For Bullseye, it's neccessary to switch the network configuration to using NetworkManager first. `sudo raspi-config` and then navigate `Advanced Options`>`Network Config`>`NetworkManager` (this will be automated soon.)

### Offline/pre-installation
Scripted and detailed documentation coming soon.

## Configuration
No configuration is neccessary for basic use. Provisioning mode will start a hotspot when either not configured (no /etc/viam.json) or not online.

### Additional Networks (Optional)
To add additional networks to an already-only device, go to the "Raw JSON" button on the Config tab for your robot/device in https://app.viam.com

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
Note: the `hotspot_password` overrides the default `viamsetup` password used to connect to the hotspot if you wish to further secure things. It is optional and can be omitted entirely.

## Use
Provisioning mode will start a hotspot when either not configured (no /etc/viam.json) or not online. By default, the wifi SSID will be `viam-setup-$HOSTNAME`. The default password is `viamsetup`. After connecting with a mobile device, you should be redirected to a sign-in page. If you are using a laptop or are not redirected, try opening http://viam.setup/ in a browswer. From the portal page, you can select an SSID and provide a password to allow your device to connect. The setup hotspot will disappear (and disconnect your mobile device) while the device attempts connection. If the hotspot reappears, there may be have been an issue or invalid password. Please try again.
