<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

enum OtpOutboxStatus: string
{
    case Pending = 'pending';
    case Delivered = 'delivered';
    case Undeliverable = 'undeliverable';
}
