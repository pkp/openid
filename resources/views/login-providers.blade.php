{{-- OpenID Login Providers --}}
@if(!empty($providers))
<div class="openid-providers">
    <h3 class="openid-providers-heading">{{ $heading }}</h3>
    <ul id="openid-provider-list" class="openid-providers-list">
        @foreach($providers as $provider)
        <li class="openid-providers-list-item">
            <a id="openid-provider-{{ $provider['name'] }}" class="openid-provider-link"
               href="{{ $provider['url'] }}">
                <img class="openid-provider-logo" src="{{ $provider['img'] }}" alt="{{ $provider['label'] }}">
                <span>{{ $provider['label'] }}</span>
            </a>
        </li>
        @endforeach
    </ul>
</div>
@endif
