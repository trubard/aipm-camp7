import { createHmac } from "crypto";

// HMAC 서명 토큰 발급(상태 불필요).
// 페이지 로드 시 프론트가 받아 /api/chat 호출에 x-app-token 헤더로 동봉한다.
// "내 페이지에서 최근에 발급받았는가"를 저장소 없이 증명시켜 단순 봇을 막는다.
// APP_SECRET 미설정이면 빈 토큰을 반환하고, 검증 측도 미설정이면 통과시킨다.

const TTL_MS = 30 * 60 * 1000; // 30분

export default function handler(req, res) {
  const secret = process.env.APP_SECRET;
  if (!secret) {
    res.status(200).json({ token: "" });
    return;
  }
  const exp = Date.now() + TTL_MS;
  const sig = createHmac("sha256", secret).update(String(exp)).digest("hex");
  res.status(200).json({ token: `${exp}.${sig}` });
}
