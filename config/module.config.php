<?php
return array(
    'service_manager' => array(
        'invokables' => array(
            'ldc-oauth2-crypto-token-server' => 'LdcOAuth2CryptoToken\Factory\CryptoTokenServerFactory',
        ),
        'delegators' => array(
            'ZF\OAuth2\Service\OAuth2Server' => array(
                'ldc-oauth2-crypto-token-server'
            ),
        ),
    ),
);
