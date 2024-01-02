// Assuming this is what your Profile looks like
export interface RefreshToken {
    id: number;
    token: string;
    userAgent: string | null;
    profileId: number;
    valid: boolean;
    createdAt: Date;
}
export interface Profile {
    id: number;
    userId: number;
    role: string;  // or you might have an enum for roles
    isActive: boolean;
    refreshTokens: RefreshToken;  // Include an array of RefreshToken
}