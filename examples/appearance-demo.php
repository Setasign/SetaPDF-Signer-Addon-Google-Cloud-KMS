<?php

use setasign\SetaPDF\Signer\Module\GoogleCloudKMS\Module;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Writer\FileWriter;
use setasign\SetaPDF2\Signer\Signature\Appearance\Dynamic as DynamicAppearance;
use setasign\SetaPDF2\Signer\Signer;

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
$writer = new FileWriter($resultPath);
// create the document instance
$document = Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new Signer($document);

$field = $signer->addSignatureField(
    'Signature',
    1,
    SetaPDF_Signer_SignatureField::POSITION_RIGHT_TOP,
    ['x' => -160, 'y' => -100],
    180,
    60
);

$signer->setSignatureFieldName($field->getQualifiedName());

$appearance = new DynamicAppearance($googleCloudKmsModule);
$signer->setAppearance($appearance);

$signer->sign($googleCloudKmsModule);
