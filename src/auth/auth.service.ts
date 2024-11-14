import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import { SignUpDto } from './dto/signup.dto';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { nanoid } from 'nanoid';
import { ResetToken } from './schemas/reset-token.schema';
import { MailService } from 'src/services/mail.service';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { RolesService } from 'src/roles/roles.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private refreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name)
    private resetTokenModel: Model<ResetToken>,
    private jwtService: JwtService,
    private mailService: MailService,
    private roleService: RolesService,
  ) {}

  async signup(SignUpData: SignUpDto) {
    const { name, email, password } = SignUpData;
    const IsEmailInUse = await this.UserModel.findOne({ email: email });
    if (IsEmailInUse) {
      throw new BadRequestException('Email already in use');
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    await this.UserModel.create({
      name,
      email,
      password: hashedPassword,
    });
    return { message: 'User created successfully' };
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    const user = await this.UserModel.findOne({ email: email });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new BadRequestException('Invalid credentials');
    }

    return this.generateUserToken(user._id);
  }

  async refreshToken(token: string) {
    const refreshToken = await this.refreshTokenModel.findOne({
      token,
      expiryDate: { $gte: new Date() },
    });
    if (!refreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    return this.generateUserToken(refreshToken.userId);
  }

  async generateUserToken(userId) {
    const accessToken = this.jwtService.sign({ userId });
    const refreshToken = uuidv4();
    await this.storeRefreshToken(refreshToken, userId);
    return { accessToken, refreshToken };
  }

  async storeRefreshToken(refreshToken: string, userId: string) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);
    await this.refreshTokenModel.updateOne(
      { userId },
      { $set: { expiryDate, refreshToken } },
      { upsert: true },
    );
  }

  async changePassword(changePasswordDto: ChangePasswordDto, userID: string) {
    const { oldPassword, newPassword } = changePasswordDto;
    const user = await this.UserModel.findById(userID);
    if (!user) {
      throw new UnauthorizedException('User not found...');
    }
    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;
    const user = await this.UserModel.findOne({ email });

    if (user) {
      const expiryDate = new Date();
      expiryDate.setDate(expiryDate.getDate() + 1);

      const resetToken = nanoid(64);
      await this.resetTokenModel.create({
        token: resetToken,
        userId: user._id,
        expiryDate: expiryDate,
      });
      this.mailService.sendPasswordResetEmail(email, resetToken);
    }

    return { message: 'Email sent' };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { resetToken, newPassword } = resetPasswordDto;
    const token = await this.resetTokenModel.findOneAndDelete({
      token: resetToken,
      expiryDate: { $gte: new Date() },
    });

    if (!token) {
      throw new UnauthorizedException('Invalid Link');
    }

    const user = await this.UserModel.findById(token.userId);
    if (!user) {
      throw new InternalServerErrorException('User not found');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    return { message: 'Password reset successful' };
  }

  async getUserPermissions(userId: string) {
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new BadRequestException();
    }
    const role = await this.roleService.getRoleById(user.roleId.toString());
    return role.permissions;
  }
}
