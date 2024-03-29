<?php

use setasign\SetaPDF\Signer\Module\GoogleCloudKMS\Module;

require_once __DIR__ . '/../vendor/autoload.php';

$fileToSign = __DIR__ . '/assets/Laboratory-Report.pdf';
$resultPath = 'signed.pdf';

$settings = require 'settings.php';
$projectId = $settings['projectId'];
$locationId = $settings['locationId'];
$keyRingId = $settings['keyRingId'];
$keyId = $settings['keyId'];
$versionId = $settings['versionId'];
$cert = $settings['cert'];
$digest = $settings['digest'];

$googleCloudKmsModule = new Module(
    $projectId,
    $locationId,
    $keyRingId,
    $keyId,
    $versionId
);

$googleCloudKmsModule->setCertificate($cert);
$googleCloudKmsModule->setDigest($digest);

// create a writer instance
$writer = new SetaPDF_Core_Writer_File($resultPath);
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new SetaPDF_Signer($document);

$field = $signer->addSignatureField(
    'Signature',
    1,
    SetaPDF_Signer_SignatureField::POSITION_RIGHT_TOP,
    ['x' => -160, 'y' => -100],
    180,
    60
);

$signer->setSignatureFieldName($field->getQualifiedName());

$appearance = new SetaPDF_Signer_Signature_Appearance_Dynamic($googleCloudKmsModule);
$signer->setAppearance($appearance);

$signer->sign($googleCloudKmsModule);
