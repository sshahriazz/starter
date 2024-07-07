export type JWTPayload = {
  user_id: string;
  email: string;
  avatar: string;
  firstname?: string;
  lastname?: string;
};

export type AuthState = {
  user: { [key: string]: any };
  tokens: {
    accessToken: string;
    refreshToken: string;
  };
};
