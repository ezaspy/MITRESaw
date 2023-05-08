<!-- PROJECT LOGO -->
<p align="center">
  <h1 align="center">OpMITRE</h1>
  <p align="center">
    Collect all of MITRE ATT&amp;CK Framework into CSV, and beyond.
    <br><br>
    <a href="https://mit-license.org">
      <img src="https://img.shields.io/github/license/ezaspy/OpMITRE" alt="License: MIT">
    </a>
    <a href="https://github.com/ezaspy/OpMITRE/issues">
      <img src="https://img.shields.io/github/issues/ezaspy/OpMITRE" alt="Issues">
    </a>
    <a href="https://github.com/ezaspy/OpMITRE/network/members">
      <img src="https://img.shields.io/github/forks/ezaspy/OpMITRE" alt="Forks">
    <a href="https://github.com/ezaspy/OpMITRE/stargazers">
      <img src="https://img.shields.io/github/stars/ezaspy/OpMITRE" alt="Stars">
    </a>
    <a href="https://www.python.org">
      <img src="https://img.shields.io/badge/language-python-pink" alt="Python">
    </a>
    </a>
      <img src="https://img.shields.io/github/last-commit/ezaspy/OpMITRE" alt="Last Commit">
    </a>
    <a href="https://github.com/psf/black">
      <img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg">
    </a>
    <br><br>
  </p>
</p>

<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
* [Usage](#usage)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)
* [Acknowledgements](#acknowledgements)


<br><br>

<!-- ABOUT THE PROJECT -->
## About The Project

OpMITRE collects a CSV-formatted version of the MITRE ATT&amp;CK Framework (https://attack.mitre.org). It also provides keyword searching and Threat Actor prioritisation.<br>
Note the usage examples for keyword searching below.
<br><br>


<!-- USAGE EXAMPLES -->
## Usage
`python3 OpMITRE.py [-h] [-j] [-n{ keyword{,keyword}}] [-s] [-t]`
### Example
`python3 OpMITRE.py -t`
### Example
`python3 OpMITRE.py -t -n mining,technology,defense,law`
<br><br>

### Notices

Because the MITRE ATT&amp;CK has been built and is managed in the United States, the keywords provided need to be in US English, as opposed UK English. An example where results would not reflect the search terms provided is the word defense (US)/defence (UK).
<br><br><br>


<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
* [Img Shields](https://shields.io)
* [Choose an Open Source License](https://choosealicense.com)
* [GitHub Pages](https://pages.github.com)



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/ezaspy/bruce.svg?style=flat-square
[contributors-url]: https://github.com/ezaspy/bruce/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/ezaspy/bruce.svg?style=flat-square
[forks-url]: https://github.com/ezaspy/bruce/network/members
[stars-shield]: https://img.shields.io/github/stars/ezaspy/bruce.svg?style=flat-square
[stars-url]: https://github.com/ezaspy/bruce/stargazers
[issues-shield]: https://img.shields.io/github/issues/ezaspy/bruce.svg?style=flat-square
[issues-url]: https://github.com/ezaspy/bruce/issues
[license-shield]: https://img.shields.io/github/license/ezaspy/bruce.svg?style=flat-square
[license-url]: https://github.com/ezaspy/bruce/master/LICENSE.txt
