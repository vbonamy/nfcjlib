<div align="center">

<h1>Nfcjlib Delegated Application Management</h1>

</div>

### Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Requirements](#Requirements)
- [Tutorial](#Tutorial)
- [Acknowledgement](#acknowledgement)
- [License](#License)

## Introduction
Nfcjlib Delegated Application Management extends [Andrade/nfcjlib](https://github.com/Andrade/nfcjlib) and give some elements to create Delegated Application.
This fork uses new features on MIFARE DESFire EV2 cards but use MIFARE DESFire EV1 protocol to communicate with the cards.


## Features

- Load DamKeys with uid diversification
- Reset Damkeys (obviously currents DamKeys are required)
- Create a Delegated Application bypassing webservices mechanisms

## Requirements

- Jre-8
- Maven
- MIFARE DESFire EV2 card

## Tutorial

Anything is more simple. You can use test classes.

- `src/nfcjlib/test/CreateDamKeysTest` : To load damKeys in your card.
- `src/nfcjlib/test/CreateDamAloneTest` : To load damKeys AND create an example delegated application in your card.

## Acknowledgement

- [Andrade](https://github.com/Andrade) for the creation of nfcjlib.
- [SpringCard](https://docs.springcard.com/) for sharing their C# Desfire methods library.

## License

This fork is released under the same licence as Andrade's repo (https://github.com/hagneva1/nfcjlib/blob/master/LICENSE)
