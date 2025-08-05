import jwt from "jsonwebtoken";

const userAuth = async (req,resizeBy, next) => {
  const { token } = req.cookies;

  if (!token) {
    return res.json({
      success: false,
      message: "User Not Authorized. Login Again",
    });
  }

  try {
    const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

    if (tokenDecode) {
      req.body.userId = tokenDecode.id;
      next();
    } else {
      return res.json({
        success: false,
        message: "User Not Authorized. Login Again",
      });
    }
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};
export default userAuth;