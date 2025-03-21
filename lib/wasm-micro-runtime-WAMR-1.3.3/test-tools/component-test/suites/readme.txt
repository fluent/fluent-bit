The description of each case in the test suites, should add descriptions in this file when new cases created in the future.

suite 01-life-cycle:
case 01-install:
    install or uninstall apps for times and query apps to see if the app list is expected.
case 02-request:
    send request to an app, the app will respond specific attribute objects, host side should get them.
case 03-event:
    register event to an app, the app will send event back periodically, host side should get some payload.
case 04-request_internal:
    install 2 apps, host sends request to app2, then app2 sends request to app1, finally app1 respond specific payload to host, host side will check it.
case 05-event_internal:
    install 2 apps, host sends request to app2, then app2 subscribe app1's event, finally app1 respond specific payload to host, host side will check it.
case 06-timer:
    host send request to an app, the app then start a timer, when time goes by 2 seconds, app will respond specific payload to host, host side will check it.
case 07-sensor:
    open sensor in app and then config the sensor in on_init, finally app will respond specific payload to host, host side will check it.
case 08-on_destroy:
    open sensor in app in on_init, and close the sensor in on_destroy, host should install and uninstall the app successfully.
