import {AuthService} from './service.ts';
import {readFileSync} from 'node:fs';

function main (): void {

    let serviceConfigFileContent = readFileSync('./configs/service-config.json', 'utf8');

    let serviceConfig = JSON.parse(serviceConfigFileContent);
    let service: AuthService = new AuthService({
            port: serviceConfig.port,
            host: serviceConfig.host,
        },
        {
            host: serviceConfig.host,
            port: serviceConfig.port,
            database: serviceConfig.database,
            user: serviceConfig.user,
            password: serviceConfig.password,
        });

    service.start();

}


main()