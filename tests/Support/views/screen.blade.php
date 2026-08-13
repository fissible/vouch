{{-- Reference renderer. TEST-ONLY: never published, never routed, never registered in production. --}}
<div class="vouch-screen" data-step="{{ $screen['step'] }}">
    @if (! empty($screen['errors']))
        <ul class="vouch-errors">
            @foreach ($screen['errors'] as $error)
                <li>{{ $error }}</li>
            @endforeach
        </ul>
    @endif

    @if (! empty($screen['offeredFactors']))
        <ul class="vouch-factors">
            @foreach ($screen['offeredFactors'] as $factor)
                <li data-factor="{{ $factor['factorId'] }}" data-default="{{ $factor['isDefault'] ? '1' : '0' }}">
                    {{ $factor['label'] }}
                </li>
            @endforeach
        </ul>
    @endif

    <form method="post">
        @foreach ($screen['fields'] as $field)
            <input
                name="{{ $field['name'] }}"
                type="{{ $field['type'] }}"
                autocomplete="{{ $field['autocomplete'] }}"
                @if ($field['maxLength'] !== null) maxlength="{{ $field['maxLength'] }}" @endif
            >
        @endforeach
        <input type="hidden" name="handle" value="{{ $handle ?? '' }}">
    </form>

    @if ($screen['retry'] !== null)
        <p class="vouch-retry">{{ json_encode($screen['retry']) }}</p>
    @endif
</div>
