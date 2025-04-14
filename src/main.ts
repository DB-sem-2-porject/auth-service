import {AuthService} from './service.ts';
import {readFileSync} from 'node:fs';

function main (): void {

    let serviceConfigFileContent = readFileSync('./configs/service-config.json', 'utf8');

    let serviceConfig = JSON.parse(serviceConfigFileContent);
    let service: AuthService = new AuthService({
            port: serviceConfig.port,
            host: serviceConfig.host,
        });

    service.start();

}


main()