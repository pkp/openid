<?php

namespace APP\plugins\generic\openid\classes;


class OpenIDProvider
{
    public function __construct(
        public string $name,
        public string $configUrl,
        ) 
    {}

    public function toJson(): string {
        return json_encode(get_object_vars($this));
    }


    public static function fromJson(string $json): self {
        $data = json_decode($json, true);
                
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException('Invalid JSON');
        }

        if (!isset($data['name'], $data['configUrl'])) {
            throw new \InvalidArgumentException('Missing required fields');
        }

        return new self($data['name'], $data['configUrl']);
    }
}
