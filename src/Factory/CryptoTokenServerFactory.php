<?php

namespace LdcOAuth2CryptoToken\Factory;

use Zend\ServiceManager\DelegatorFactoryInterface;
use Zend\ServiceManager\Exception\ServiceNotCreatedException;
use Zend\ServiceManager\ServiceLocatorInterface;
use ZF\OAuth2\Adapter\MongoAdapter;
use ZF\OAuth2\Adapter\PdoAdapter;

class CryptoTokenServerFactory implements DelegatorFactoryInterface
{

    /**
     * Create and return an OAuth2 storage adapter instance.
     *
     * @param array $config
     * @param ServiceLocatorInterface $services
     * @return PdoAdapter|MongoAdapter|array A PdoAdapter, MongoAdapter, or array of storage instances.
     */
    private static function createStorage(array $config, ServiceLocatorInterface $services)
    {
        if (isset($config['adapter']) && is_string($config['adapter'])) {
            return self::createStorageFromAdapter($config['adapter'], $config, $services);
        }

        if (isset($config['storage'])
            && (is_string($config['storage']) || is_array($config['storage']))
        ) {
            return self::createStorageFromServices($config['storage'], $services);
        }

        throw new ServiceNotCreatedException('Missing or invalid storage adapter information for OAuth2');
    }

    /**
     * Create an OAuth2 storage instance based on the adapter specified.
     *
     * @param string $adapter One of "pdo" or "mongo".
     * @param array $config
     * @param ServiceLocatorInterface $services
     * @return PdoAdapter|MongoAdapter
     * @throws ServiceNotCreatedException
     */
    private static function createStorageFromAdapter($adapter, array $config, ServiceLocatorInterface $services)
    {
        switch (strtolower($adapter)) {
            case 'pdo':
                return self::createPdoAdapter($config);
            case 'mongo':
                return self::createMongoAdapter($config, $services);
            default:
                throw new ServiceNotCreatedException('Invalid storage adapter type for OAuth2');
        }
    }

    /**
     * Creates the OAuth2 storage from services.
     *
     * @param string|string[] $storage A string or an array of strings; each MUST be a valid service.
     * @param ServiceLocatorInterface $services
     * @return array
     */
    private static function createStorageFromServices($storage, ServiceLocatorInterface $services)
    {
        $storageServices = [];
        if (is_string($storage)) {
            $storageServices[] = $storage;
        }
        if (is_array($storage)) {
            $storageServices = $storage;
        }

        $storage = [];
        foreach ($storageServices as $key => $service) {
            $storage[$key] = $services->get($service);
        }
        return $storage;
    }

    /**
     * Create and return an OAuth2 PDO adapter.
     *
     * @param array $config
     * @return PdoAdapter
     */
    private static function createPdoAdapter(array $config)
    {
        return new PdoAdapter(
            self::createPdoConfig($config),
            self::getOAuth2ServerConfig($config)
        );
    }

    /**
     * Create and return an OAuth2 Mongo adapter.
     *
     * @param array $config
     * @param ServiceLocatorInterface $services
     * @return MongoAdapter
     */
    private static function createMongoAdapter(array $config, ServiceLocatorInterface $services)
    {
        return new MongoAdapter(
            self::createMongoDatabase($config, $services),
            self::getOAuth2ServerConfig($config)
        );
    }

    /**
     * Create and return the configuration needed to create a PDO instance.
     *
     * @param array $config
     * @return array
     */
    private static function createPdoConfig(array $config)
    {
        if (! isset($config['dsn'])) {
            throw new ServiceNotCreatedException(
                'Missing DSN for OAuth2 PDO adapter creation'
            );
        }

        $username = isset($config['username']) ? $config['username'] : null;
        $password = isset($config['password']) ? $config['password'] : null;
        $options  = isset($config['options'])  ? $config['options'] : [];

        return [
            'dsn'      => $config['dsn'],
            'username' => $username,
            'password' => $password,
            'options'  => $options,
        ];
    }

    /**
     * Create and return a Mongo database instance.
     *
     * @param array $config
     * @param ServiceLocatorInterface $services
     * @return \MongoDB
     */
    private static function createMongoDatabase(array $config, ServiceLocatorInterface $services)
    {
        $dbLocatorName = isset($config['locator_name'])
            ? $config['locator_name']
            : 'MongoDB';

        if ($services->has($dbLocatorName)) {
            return $services->get($dbLocatorName);
        }

        if (! isset($config['database'])) {
            throw new ServiceNotCreatedException(
                'Missing OAuth2 Mongo database configuration'
            );
        }

        $options = isset($config['options']) ? $config['options'] : [];
        $options['connect'] = false;
        $server  = isset($config['dsn']) ? $config['dsn'] : null;
        $mongo   = new \MongoClient($server, $options);
        return $mongo->{$config['database']};
    }

    /**
     * Retrieve oauth2-server-php storage settings configuration.
     *
     * @return array
     */
    private static function getOAuth2ServerConfig($config)
    {
        $oauth2ServerConfig = [];
        if (isset($config['storage_settings']) && is_array($config['storage_settings'])) {
            $oauth2ServerConfig = $config['storage_settings'];
        }

        return $oauth2ServerConfig;
    }


    public function createDelegatorWithName(ServiceLocatorInterface $services, $name, $requestedName, $callback)
    {
        $closure = call_user_func($callback);

        $config = $services->get('Config');


        if (!isset($config['ldc-oauth2-crypto-token']['keys']['public_key']) || !file_exists($config['ldc-oauth2-crypto-token']['keys']['public_key'])) {
            throw new Exception\KeyFileNotFoundException('You must provide a public key to use LdcOAuth2CryptoToken!');
        }
        if (!isset($config['ldc-oauth2-crypto-token']['keys']['private_key']) || !file_exists($config['ldc-oauth2-crypto-token']['keys']['private_key'])) {
            throw new Exception\KeyFileNotFoundException('You must provide a private key to use LdcOAuth2CryptoToken!');
        }

        // Load the public and private key files
        $publicKey  = file_get_contents($config['ldc-oauth2-crypto-token']['keys']['public_key']);
        $privateKey = file_get_contents($config['ldc-oauth2-crypto-token']['keys']['private_key']);

        // Instantiate in-memory storage for our keys
        $storage = new \OAuth2\Storage\Memory(array(
            'keys' => array(
                'public_key'  => $publicKey,
                'private_key' => $privateKey,
            ),
        ));

        return function ($type = null) use ($closure, $services, $storage, $config) {

            $server = call_user_func($closure, $type);

            $mvcAuthConfig = isset($config['zf-mvc-auth']['authentication']['adapters'])
                ? $config['zf-mvc-auth']['authentication']['adapters']
                : [];

            $coreStorage = null;
            if ($config['ldc-oauth2-crypto-token']['inject_existing_storage'] === true) {

                foreach ($mvcAuthConfig as $name => $adapterConfig) {
                    if (!isset($adapterConfig['storage']['route'])) {
                        // Not a zf-oauth2 config
                        continue;
                    }

                    if ($type !== $adapterConfig['storage']['route']) {
                        continue;
                    }

                    // Found!
                    $coreStorage = self::createStorage($adapterConfig['storage'], $services);
                }
            }

            // Make the "access_token" storage use Crypto Tokens instead of a database
            $cryptoStorage = new \OAuth2\Storage\JwtAccessToken($storage, $coreStorage);
            $server->addStorage($cryptoStorage, 'access_token');

            // make the "token" response type a CryptoToken
            $cryptoResponseType = new \OAuth2\ResponseType\JwtAccessToken($storage, $coreStorage);
            $server->addResponseType($cryptoResponseType);

            return $server;
        };
    }
}
