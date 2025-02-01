# Polychat Dissector
This discetor is intended to parse and display a simple chat protocol in Wireshark.  It needed to be added to and build with the wireshark source.

## Note

This dissector is setup to find packets on port 8000. Life is easiest if you use this port. This can be changed in the wireshark settings.

## Get the Wireshark source code

Get the [source](https://gitlab.com/wireshark/wireshark)

Make sure you have the right [toolchain](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterTools.html) for your OS

I found this [resource](https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcBuildFirstTime.html) and this [article](https://blog.fjh1997.top/2019/03/29/show-you-how-to-compile-the-c-language-plugin-for-wireshark-3.1-step-by-step-(windows-platform-2019-3-20)/) helpful for building the pluging with wireshark

## Binary

I compiled a .so on an Apple Silicon MAC M4 running 15.3/Sequoia fro Wireshark 4.4.3.  This .so should work on other 4.4 versions of wireshark and other apple silicon macs. There is a user specifici plugins folder for wireshark, but I could not get that to work.  I found that putting it into the application bundle directly worked.  In my case this is:

```
/Applications/Wireshark.app/Contents/PlugIns/wireshark/4-4/epan/
```

So to copy the .so fro the root of this repo:

```
cp ./binaries/4.4.3/mac/polychat.so /Applications/Wireshark.app/Contents/PlugIns/wireshark/4-4/epan/
```

And then start/restart wireshark.

If someone builds bianries for other version / os I am happy to host them here.

