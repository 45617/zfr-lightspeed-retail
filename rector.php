<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;

use Rector\PHPUnit\Set\PHPUnitSetList;

return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/config',
        __DIR__ . '/src',
        __DIR__ . '/test',
    ])
    // uncomment to reach your current PHP version
    ->withPhpSets(php82: true)
    ->withSets([PHPUnitSetList::PHPUNIT_100])
    ->withComposerBased(phpunit: true)
    ->withTypeCoverageLevel(0)
    ->withDeadCodeLevel(0)
    ->withCodeQualityLevel(0);
