import jwt from 'jsonwebtoken'
import * as Hapi from "@hapi/hapi";



export interface AuthServiceOptions {
    port: number;
    host?: string;
}
interface AuthPayload {
    email: string;
    password: string;
}

export class AuthService {
    private port: number;
    private host: string;
    private server: Hapi.Server;
    private secretPhrase: string = "secret";


    constructor(serviceOptions: AuthServiceOptions) {
        this.port = serviceOptions.port;
        this.host = serviceOptions.host || 'localhost';

        this.server = Hapi.server({
            port: serviceOptions.port,
            host: serviceOptions.host || 'localhost',
        });

        this.server.route({
            method: 'POST',
            path: '/auth',
            handler: this.authHandler.bind(this)
        });
    }

    private validateToken(token: string): string | jwt.JwtPayload | null {
        try {
            return jwt.verify(token, this.secretPhrase);
        } catch (err) {
            console.error('Invalid token:', err);
            return null;
        }
    }

    private async authHandler(request: Hapi.Request, responseToolkit: Hapi.ResponseToolkit) {
        const authHeader = request.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return responseToolkit.response({ error: 'Missing or invalid token' }).code(401);
        }

        const token = authHeader.split(' ')[1];
        const decoded = this.validateToken(token);

        if (!decoded) {
            return responseToolkit.response({ error: 'Invalid or expired token' }).code(401);
        }

        // Можно использовать decoded, например decoded.email
        return responseToolkit.response({ message: 'Access granted', user: decoded }).code(200);
    }


    public start(): void {

        try {
            this.server.start().then(r => {
            });
            process.on('SIGINT', async () => {
                console.log('\nStopping server...');
                await this.server.stop();
                process.exit(0);
            });
            console.log(`Server running at: ${this.server.info.uri}`);
        } catch (err) {
            console.error('Failed to start server:', err);
            process.exit(1);
        }
    }


}