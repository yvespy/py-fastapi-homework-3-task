from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from starlette.responses import JSONResponse

from config import get_jwt_auth_manager
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema
from schemas.accounts import UserActivationResponseSchema, MessageResponseSchema, PasswordResetRequestSchema, \
    PasswordResetCompleteRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, \
    TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistrationRequestSchema,
                        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                        db: AsyncSession = Depends(get_db)):
    db_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    if db_user.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        hashed = hash_password(user_data.password)
        result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        group = result.scalar_one_or_none()
        if not group:
            raise HTTPException(
                status_code=500,
                detail="Default user group not found."
            )
        new_user = UserModel(
            email=user_data.email,
            _hashed_password=hashed,
            group_id=group.id
        )
        db.add(new_user)
        await db.flush()

        activation_token_value = jwt_manager.create_access_token({
            "sub": str(new_user.id),
            "email": new_user.email
        })
        activation_token = ActivationTokenModel(
            user=new_user,
            token=activation_token_value,
            expires_at=datetime.utcnow() + timedelta(days=1)
        )

        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)
        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", response_model=UserActivationResponseSchema)
async def activate_user(user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    token_request = await db.execute(
        select(ActivationTokenModel)
        .join(ActivationTokenModel.user)
        .options(joinedload(ActivationTokenModel.user))
        .where(UserModel.email == user_data.email, ActivationTokenModel.token == user_data.token)
    )
    token_result = token_request.scalar_one_or_none()
    if not token_result:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if token_result.user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    expires_at = token_result.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    token_result.user.is_active = True
    await db.delete(token_result)
    await db.commit()
    await db.refresh(token_result.user)
    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset_request(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db),
                                 jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    db_user = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == user_data.email)
    )
    user = db_user.scalar_one_or_none()
    if not user or not user.is_active:
        return JSONResponse({"message": "If you are registered, you will receive an email with instructions."})
    if user.password_reset_token:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
    password_token_value = jwt_manager.create_refresh_token({"sub": user.email})
    password_reset_token = PasswordResetTokenModel(
        user=user,
        token=password_token_value,
        expires_at=datetime.utcnow() + timedelta(days=1)
    )
    db.add(password_reset_token)
    await db.commit()
    await db.refresh(user)
    return JSONResponse({"message": "If you are registered, you will receive an email with instructions."})


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def password_reset_complete(user_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db),
                                  jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    db_user = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == user_data.email)
    )
    user = db_user.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        jwt_manager.verify_refresh_token_or_raise(user_data.token)
    except (TokenExpiredError, InvalidTokenError):
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    if not user.password_reset_token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    expires_at = user.password_reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        hashed = hash_password(user_data.password)
        user._hashed_password = hashed
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        await db.refresh(user)
        return JSONResponse({"message": "Password reset successfully."})

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema)
async def login_user(
        user_data: UserLoginRequestSchema, db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    db_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = db_user.scalar_one_or_none()
    if not user or not verify_password(user_data.password, user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token_value = jwt_manager.create_access_token({"user_id": user.id, "email": user.email})
        refresh_token_value = jwt_manager.create_refresh_token({"user_id": user.id, "email": user.email})
        refresh_token = RefreshTokenModel(
            user_id=int(user.id),
            token=refresh_token_value,
            expires_at=datetime.utcnow() + timedelta(minutes=60 * 24 * 7)
        )
        db.add(refresh_token)
        await db.commit()
        await db.refresh(refresh_token)
        return JSONResponse(
            status_code=201,
            content={
                "access_token": access_token_value,
                "refresh_token": refresh_token.token,
                "token_type": "bearer"
            }
        )
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
        user_refresh_token: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager=Depends(get_jwt_auth_manager),
):
    try:
        check_token = jwt_manager.decode_refresh_token(
            token=user_refresh_token.refresh_token
        )
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    check_token_in_database = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == user_refresh_token.refresh_token
        )
    )
    result_token = check_token_in_database.scalar_one_or_none()

    if not result_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = check_token.get("user_id")
    get_user_with_token = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    user_result = get_user_with_token.scalar_one_or_none()

    if not user_result:
        raise HTTPException(status_code=404, detail="User not found.")

    create_access_token = jwt_manager.create_access_token({"user_id": user_result.id})
    return TokenRefreshResponseSchema(access_token=create_access_token)
