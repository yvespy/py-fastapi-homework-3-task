from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from config.settings import Settings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema
from schemas.accounts import UserActivationResponseSchema, MessageResponseSchema, PasswordResetRequestSchema, \
    PasswordResetCompleteRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, \
    TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.utils import generate_secure_token

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    email_result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    existing_user = email_result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    group_result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_group = group_result.scalar_one_or_none()

    db_user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=user_group.id,
    )

    try:
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema(
        id=db_user.id,
        email=db_user.email,
    )


@router.post("/activate/", response_model=UserActivationResponseSchema)
async def activate_user(user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    user_result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    db_user = user_result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )
    token_result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == db_user.id,
            ActivationTokenModel.token == user_data.token,
        ),
    )
    token_record = token_result.scalar_one_or_none()

    if token_record.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    await db.delete(token_record)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset_request(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = result.scalar_one_or_none()

    if user is user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

        reset_token = PasswordResetTokenModel(user_id=user.id, token=generate_secure_token())
        db.add(reset_token)
        await db.commit()

    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def password_reset_complete(user_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    user_result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    token_result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == user_data.token,
        )
    )
    token_record = token_result.scalar_one_or_none()
    if not token_record:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id,
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    if token_record.expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    try:
        user.password = user_data.password
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
    return MessageResponseSchema(message="Password reset successful.")


@router.post("/login/", response_model=UserLoginResponseSchema)
async def login_user(
        user_data: UserLoginRequestSchema, db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: Settings = Depends(get_settings)
):
    user_result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = user_result.scalar_one_or_none()

    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    access_token = jwt_manager.create_access_token({"sub": str(user.id)})
    refresh_token_str = jwt_manager.create_refresh_token({"sub": str(user.id)})

    refresh_token = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token_str
    )

    try:
        db.add(refresh_token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token_str,
        token_type="bearer",
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(token_data: TokenRefreshRequestSchema, db: AsyncSession = Depends(get_db),
                               jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = int(payload.get("sub"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == token_data.token))
    db_token = result.scalar_one_or_none()
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"sub": str(user.id)})

    return TokenRefreshResponseSchema(access_token=access_token)
