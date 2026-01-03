## What is this?

a simple script that just checks all the inotify instances in every process
it has access and currently kills every one that has more than 40k watches
ideally this will be a simple tui to kill those process

## Why?

for some reason or some misconfiguration nx seems to spam inotify watches

## How to build?

install the odin compiler and run
```bash
odin build .
```

maybe in the future this will have a release build

## TODO:
- [ ] tui
- [ ] maybe kill process over a threshold using args

## Thanks to:
[inotify-info made by mikesart](https://github.com/mikesart/inotify-info)
most of the code that reads the data from process is basically a translation from this project 

[Odin lang](https://github.com/odin-lang/Odin)
