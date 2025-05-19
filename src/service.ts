import jwt from 'jsonwebtoken'
import * as Hapi from "@hapi/hapi";
import pg from 'pg';
import { QueryResult } from "pg";
const { Pool } = pg;



export interface AuthServiceOptions {
    port: number;
    host?: string;
}
interface AuthPayload {
    email: string;
    password: string;
}

export interface LoginServiceOptions {
    port: number;
    host?: string;
}
export interface DatabaseOptions {
    user: string;
    host?: string;
    database: string;
    password: string;
    port: number;
}
interface LoginPayload {
    email: string;
    password: string;
}

export class AuthService {
    private port: number;
    private host: string;
    private server: Hapi.Server;
    private secretPhrase: string = "secret";
    private pool: pg.Pool;


    constructor(serviceOptions: AuthServiceOptions, databaseOptions: DatabaseOptions) {
        this.port = serviceOptions.port;
        this.host = serviceOptions.host || 'localhost';

        this.server = Hapi.server({
            port: serviceOptions.port,
            host: serviceOptions.host || 'localhost',
        });

        this.pool = new Pool({
            host: databaseOptions.host || 'localhost',
            port: databaseOptions.port,
            database: databaseOptions.database,
            user: databaseOptions.user,
            password: databaseOptions.password,
        });

        this.server.route({
            method: 'POST',
            path: '/auth',
            handler: this.authHandler.bind(this)
        });

        this.server.route({
            method: 'POST',
            path: '/login',
            handler: this.loginHandler.bind(this)
        });

        this.server.route({
            method: 'POST',
            path: '/request-password-reset',
            handler: this.resetPasswordHandler.bind(this)
        });
    }

    private async resetPasswordHandler(request: Hapi.Request, responseToolkit: Hapi.ResponseToolkit) {
        const {email} = request.payload as { email: string };

        // Проверь, есть ли такой пользователь
        const result = await this.pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rowCount === 0) {
            return responseToolkit.response({message: 'If that email exists, a reset link has been sent.'}).code(200);
        }

        const token = jwt.sign({email}, this.secretPhrase, {expiresIn: '15m'});

        await this.pool.query('UPDATE users SET reset_token = $1 WHERE email = $2', [token, email]);

        await this.sendResetEmail(email, token);

        return responseToolkit.response({message: 'If that email exists, a reset link has been sent.'}).code(200);
    };

    private async sendResetEmail(email: string, token: string): Promise<void> {
        // Тут должна быть интеграция с реальной почтой
        console.log(`Send reset link: http://localhost:3000/reset-password?token=${token}`);
    }
    private generateToken(payload: object): string {
        return jwt.sign(payload, this.secretPhrase, {
            expiresIn: '1d',
        });
    }


    private async login(data: LoginPayload): Promise<boolean> {
        const { email, password } = data;

        try {
            const result: QueryResult = await this.pool.query(
                'select password from users where email = $1',
                [email]
            );

            if (result.rowCount === 0) {
                return false;
            }

            const storedPassword = result.rows[0].password;

            // Тут можно добавить хеширование через bcrypt:
            // return await bcrypt.compare(password, storedPassword);

            return storedPassword === password; // временная проверка без хеширования
        } catch (error) {
            console.error('Login failed:', error);
            return false;
        }
    }

    private async loginHandler(request: Hapi.Request, responseToolkit: Hapi.ResponseToolkit) {
        const data: LoginPayload = request.payload as LoginPayload;
        const isLogin: boolean = await this.login(data);

        if (!isLogin) {
            return responseToolkit
                .response({ error: 'Invalid email or password' })
                .code(401); // Unauthorized
        }
        console.log("login success");
        const token = this.generateToken(data);
        return responseToolkit
            .response({ token })
            .code(200); // OK
    }

    private validateToken(token: string): string | jwt.JwtPayload | null {
        try {
            return jwt.verify(token, this.secretPhrase);
        } catch (err) {
            // console.error('Invalid token:', err);
            console.error('Invalid token: ', token);

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
        console.log('Token is valid')
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