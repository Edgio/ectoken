![Verizon Digital Media Services](https://images.verizondigitalmedia.com/2016/03/vdms-30.png)

# Token Generator for Edgecast Token-Based Authentication

Token-Based Authentication safeguards against hotlinking by adding a token requirement to requests for content secured by it. This token, which must be defined in the request URL's query string, defines the criteria that must be met before the requested content may be served via the CDN. This repository contains the following token generation resources:
- [Linux binaries and Windows executable](https://github.com/VerizonDigital/ectoken/releases/latest)
- Source code for various languages (e.g., [C#](c#-ectoken/.), [Python](python-ectoken/.), [PHP](php-ectoken/.), etc.)

## Quick Start

1. Leverage this token generator by either:
   - Downloading a Linux binary and/or Windows executable.
   - Cloning this repository and then incorporating the source code for the desired language in your application.
2. Create a script to generate tokens for your content.
3. Either update your static links or dynamically generate links that include a query string set to a token that defines the requirements that must be met before that content may be served.

## Usage

Use the following syntax to specify a single parameter:

`ectoken3 <KeyName> "<Parameter>=<Value>"`

Use the following syntax to specify multiple parameters:

`ectoken3 <KeyName> "<Parameter1>=<Value>&<Parameter2>=<Value1>,<Value2>"`

## Contributing

Contributions are welcome! Please review our [contribution guidelines](CONTRIBUTING.md).

## More Information

Please refer to the CDN Help Center, which is available from within the MCC, for more information (e.g., parameter names and usage).

## License

[View legal and licensing information.](LICENSE.txt)