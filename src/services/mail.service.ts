import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      auth: {
        user: 'lilla.terry55@ethereal.email',
        pass: 'yQQSg25MR1QwugbNnN',
      },
    });
  }

  async sendPasswordResetEmail(to: string, token: string) {
    const resetLink = `http://www.frontUrl.com/reset-password?token=${token}`;
    const mailOptions = {
      from: 'Auth Backend Service',
      to: to,
      subject: 'Password Reset Request',
      html: `<p>You requested a password reset. Click the link below to reset your password:</p> <a href="${resetLink}">Reset Password</a>`,
    };
    await this.transporter.sendMail(mailOptions);
  }
}
