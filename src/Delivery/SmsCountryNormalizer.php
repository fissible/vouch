<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

use libphonenumber\NumberParseException;
use libphonenumber\PhoneNumberFormat;
use libphonenumber\PhoneNumberUtil;
use InvalidArgumentException;

/**
 * Parses and canonicalizes SMS targets once at the delivery input boundary.
 *
 * No default region is accepted: an unqualified number is ambiguous and must
 * not be guessed into a country allow-list or spend bucket.
 */
final readonly class SmsCountryNormalizer
{
    public function __construct(private PhoneNumberUtil $phoneNumbers)
    {
    }

    public static function defaults(): self
    {
        return new self(PhoneNumberUtil::getInstance());
    }

    public function normalize(string $value): NormalizedPhoneNumber
    {
        try {
            $number = $this->phoneNumbers->parse($value, null);
        } catch (NumberParseException $exception) {
            throw new InvalidArgumentException(
                'The SMS identifier is not a parseable international phone number.',
                previous: $exception,
            );
        }

        if (! $this->phoneNumbers->isValidNumber($number)) {
            throw new InvalidArgumentException(
                'The SMS identifier is not a valid international phone number.',
            );
        }

        $country = $this->phoneNumbers->getRegionCodeForNumber($number);

        if (! is_string($country) || $country === '' || $country === '001') {
            throw new InvalidArgumentException(
                'The SMS identifier has no unambiguous ISO country.',
            );
        }

        return new NormalizedPhoneNumber(
            $this->phoneNumbers->format($number, PhoneNumberFormat::E164),
            $country,
        );
    }
}
