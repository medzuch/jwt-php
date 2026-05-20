<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;
use PhpCsFixer\Runner\Parallel\ParallelConfigFactory;

$finder = Finder::create()
    ->in([__DIR__ . '/src', __DIR__ . '/tests'])
    ->name('*.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);

return (new Config())
    ->setParallelConfig(ParallelConfigFactory::detect())
    ->setRiskyAllowed(true)
    ->setFinder($finder)
    ->setCacheFile(__DIR__ . '/var/php-cs-fixer.cache')
    ->setRules([
        '@PER-CS' => true,
        '@PER-CS:risky' => true,
        '@PHP83Migration' => true,
        '@PHP82Migration:risky' => true,
        '@PHPUnit100Migration:risky' => true,
        '@Symfony' => true,
        '@Symfony:risky' => true,

        // Project-specific tweaks
        'declare_strict_types' => true,
        'strict_param' => true,
        'strict_comparison' => true,
        'native_function_invocation' => [
            'include' => ['@all'],
            'scope' => 'namespaced',
            'strict' => true,
        ],
        'global_namespace_import' => [
            'import_classes' => true,
            'import_constants' => true,
            'import_functions' => true,
        ],
        'final_class' => true,
        'final_internal_class' => true,
        'self_static_accessor' => true,
        'phpdoc_to_comment' => false,         // we use docblocks for PHPStan hints
        'yoda_style' => false,
        'concat_space' => ['spacing' => 'one'],
        'ordered_class_elements' => true,
        'ordered_imports' => [
            'sort_algorithm' => 'alpha',
            'imports_order' => ['class', 'function', 'const'],
        ],
        'phpdoc_align' => ['align' => 'left'],
        'no_superfluous_phpdoc_tags' => [
            'allow_mixed' => true,
            'remove_inheritdoc' => true,
        ],
        'general_phpdoc_annotation_remove' => [
            'annotations' => ['author', 'package'],
        ],
        // PHPUnit-friendly
        'php_unit_test_class_requires_covers' => false,
        'php_unit_internal_class' => false,
        // Security-relevant: never use short array syntax inconsistencies
        'array_syntax' => ['syntax' => 'short'],
    ]);
