import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import { Op } from "sequelize";

const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findByPk(userId);
        const accessToken = jwt.sign(
            {
                id: user.id,
                email: user.email,
                username: user.username,
                fullName: user.fullName
            },
            process.env.ACCESS_TOKEN_SECRET,
            {
                expiresIn: process.env.ACCESS_TOKEN_EXPIRY
            }
        );
        const refreshToken = jwt.sign(
            {
                id: user.id
            },
            process.env.REFRESH_TOKEN_SECRET,
            {
                expiresIn: process.env.REFRESH_TOKEN_EXPIRY
            }
        );

        user.refreshToken = refreshToken;
        await user.save();

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token");
    }
};

const registerUser = async (req, res, next) => {
    try {
        const { fullName, email, username, password } = req.body;

        if (
            [fullName, email, username, password].some((field) => field?.trim() === "")
        ) {
            throw new ApiError(400, "All fields are required");
        }

        const existingUser = await User.findOne({
            where: {
                [Op.or]: [{ username }, { email }]
            }
        });

        if (existingUser) {
            throw new ApiError(409, "User with email or username already exists");
        }

        const user = await User.create({
            fullName,
            email,
            password,
            username: username.toLowerCase()
        });

        const createdUser = await User.findByPk(user.id, {
            attributes: { exclude: ['password', 'refreshToken'] }
        });

        if (!createdUser) {
            throw new ApiError(500, "Something went wrong while registering the user");
        }

        return res.status(201).json(
            new ApiResponse(200, createdUser, "User registered successfully")
        );
    } catch (error) {
        next(error);
    }
};

const loginUser = async (req, res, next) => {
    try {
        const { email, username, password } = req.body;

        if (!username && !email) {
            throw new ApiError(400, "Username or email is required");
        }

        if (!password) {
            throw new ApiError(400, "Password is required");
        }

        const whereClause = {};
        if (username) {
            whereClause.username = username.toLowerCase();
        }
        if (email) {
            whereClause.email = email.toLowerCase();
        }

        const user = await User.findOne({
            where: whereClause
        });

        if (!user) {
            throw new ApiError(404, "User does not exist");
        }

        const isPasswordValid = await user.isPasswordCorrect(password);

        if (!isPasswordValid) {
            throw new ApiError(401, "Invalid user credentials");
        }

        const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user.id);

        const loggedInUser = await User.findByPk(user.id, {
            attributes: { exclude: ['password', 'refreshToken'] }
        });

        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        };

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    {
                        user: loggedInUser,
                        accessToken,
                        refreshToken
                    },
                    "User logged in successfully"
                )
            );
    } catch (error) {
        next(error);
    }
};

const logoutUser = async (req, res, next) => {
    try {
        await User.update(
            { refreshToken: null },
            { where: { id: req.user.id } }
        );

        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        };

        return res
            .status(200)
            .clearCookie("accessToken", options)
            .clearCookie("refreshToken", options)
            .json(new ApiResponse(200, {}, "User logged out"));
    } catch (error) {
        next(error);
    }
};

const refreshAccessToken = async (req, res, next) => {
    try {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

        if (!incomingRefreshToken) {
            throw new ApiError(401, "unauthorized request");
        }

        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        const user = await User.findByPk(decodedToken.id);

        if (!user) {
            throw new ApiError(401, "Invalid refresh token");
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used");
        }

        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        };

        const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user.id);

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed"
                )
            );
    } catch (error) {
        next(error);
    }
};

const changeCurrentPassword = async (req, res, next) => {
    try {
        const { oldPassword, newPassword } = req.body;

        const user = await User.findByPk(req.user?.id);

        const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

        if (!isPasswordCorrect) {
            throw new ApiError(400, "Invalid old password");
        }

        user.password = newPassword;
        await user.save();

        return res
            .status(200)
            .json(new ApiResponse(200, {}, "Password changed successfully"));
    } catch (error) {
        next(error);
    }
};

const getCurrentUser = async (req, res, next) => {
    try {
        return res
            .status(200)
            .json(new ApiResponse(200, req.user, "User fetched successfully"));
    } catch (error) {
        next(error);
    }
};

const updateAccountDetails = async (req, res, next) => {
    try {
        const { fullName, email } = req.body;

        if (!fullName || !email) {
            throw new ApiError(400, "All fields are required");
        }

        const user = await User.update(
            {
                fullName,
                email
            },
            {
                where: { id: req.user?.id },
                returning: true
            }
        );

        return res
            .status(200)
            .json(new ApiResponse(200, user[1][0], "Account details updated successfully"));
    } catch (error) {
        next(error);
    }
};

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails
};