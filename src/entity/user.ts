import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn,
} from 'typeorm';
import "reflect-metadata"

@Entity({ name: 'users' })
export class User {
    @PrimaryGeneratedColumn({
        type: 'int',
        name: 'id'
    })
    id!: number;

    @Column({
        type: 'varchar',
        length: 100,
        unique: true
    })
    email!: string;

    @Column({
        type: 'varchar',
        length: 255
    })
    password!: string;

    @Column({
        name: 'reset_token',
        type: 'text',
        nullable: true
    })
    resetToken?: string;

    @CreateDateColumn({
        name: 'registration_date',
        type: 'timestamp',
        default: () => 'now()'
    })
    registrationDate!: Date;

    @UpdateDateColumn({
        name: 'last_login',
        type: 'timestamp',
        nullable: true
    })
    lastLogin?: Date;

    constructor(data?: { email: string; password: string; resetToken?: string }) {
        if (data) {
            this.email = data.email;
            this.password = data.password;
            this.resetToken = data.resetToken;
        }
    }
}