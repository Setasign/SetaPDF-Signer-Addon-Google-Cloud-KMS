#  SetaPDF-Signer component module for the Google Cloud KMS.

This package offers module for the [SetaPDF-Signer](https://www.setasign.com/signer) component that allow you to use
the [Google Cloud Key Management Service](https://cloud.google.com/kms/docs) to **digital sign PDF documents in pure PHP**.

## Requirements

To use this package you need credentials for the Google Cloud KMS.

This package is developed and tested on PHP >= 5.6. Requirements of the [SetaPDF-Signer](https://www.setasign.com/signer)
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

## Installation
Add following to your composer.json:

```json
{
    "require": {
        "setasign/setapdf-signer-addon-google-cloud-kms": "^1.0"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

and execute `composer update`. You need to define the `repository` to evaluate the dependency to the
[SetaPDF-Signer](https://www.setasign.com/signer) component
(see [here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).

**Follow the [instructions to authentification](https://cloud.google.com/kms/docs/reference/libraries#setting_up_authentication) on Google Cloud KMS.**


### Evaluation version
By default this packages depends on a licensed version of the [SetaPDF-Signer](https://www.setasign.com/signer)
component. If you want to use it with an evaluation version please use following in your composer.json:

```json
{
    "require": {
        "setasign/setapdf-signer-addon-google-cloud-kms": "dev-evaluation"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

## Usage

All classes in this package are located in the namespace `setasign\SetaPDF\Signer\Module\GoogleCloudKMS`.

### The `Module` class

This is the main signature module which can be used with the [SetaPDF-Signer](https://www.setasign.com/signer)
component. Its constructor requires 5 arguments:

- `$projectId` -  Your project id
- `$locationId` -  Your location id
- `$keyRingId` -  Your key Ring id
- `$keyId` -  Your key id
- `$versionId` -  Your version id

A simple complete signature process would look like this:

```php
$googleCloudKmsModule = new setasign\SetaPDF\Signer\Module\GoogleCloudKMS\Module(
    $projectId,
    $locationId,
    $keyRingId,
    $keyId,
    $versionId
);

$cert = file_get_contents('your-cert.crt');
$googleCloudKmsModule->setCertificate($cert);
$googleCloudKmsModule->setDigest($digest);

// the file to sign
$fileToSign = __DIR__ . '/Laboratory-Report.pdf';

// create a writer instance
$writer = new SetaPDF_Core_Writer_File('signed.pdf');
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new SetaPDF_Signer($document);
$signer->sign($googleCloudKmsModule);
```

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
