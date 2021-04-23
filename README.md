# SRePlay (Strict RePlay)
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)
[![GitHub version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=gh&type=0.2&v=1.0&x2=0)](http://badge.fury.io/gh/boennemann%2Fbadges)
[![Open Source Love](https://badges.frapsoft.com/os/mit/mit.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)

**Burpsuite Plugin to bypass RePlay protection**

<img src="https://i.imgur.com/dY17I6A.png" />



### Requirements
- Burpsuite

### How to Install
<pre>Download Latest Jar from <a href="https://github.com/Ebryx/SRePlay/releases/tag/v2.0" target=_blank>Release</a> and add in burpsuite extender</pre>

### What it does
It is design for a scenario where we can't replay requests more than once as the request is getting Token from previous request's response and also when we can't make request with macros to get the token

- It will extract the value of token from the last response and automatically update the request with the new token on the fly 

### Usage Guide

The detailed usage guide can be found <a href="https://n00b.sh/posts/sreplay/" target=_blank>SRePlay - Bypass Replay Protection</a>.

### How it works
- Provide `Host URL` 
- Provide `Response parameter name` 
- Provide `Request parameter name` 
- Provide `Parameter Initial Value` 
- Press `Start SRePlay`

<img src="https://i.imgur.com/IfmjO7r.png">



### SRePlay in Action

<img src="https://i.imgur.com/69W1CL8.gif">



### Limitation
- Will only work with single thread on Scanner and Intruder 

### Tested on
- Burpsuite 2021.4
- Windows 10
- Ubuntu & PopOS

### Improvements
- Multi-session / threading support
