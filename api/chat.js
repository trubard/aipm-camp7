import Anthropic from "@anthropic-ai/sdk";
import { createHmac, timingSafeEqual } from "crypto";

// API 키는 환경변수 ANTHROPIC_API_KEY 에서 자동으로 읽어옵니다.
// (vercel dev 사용 시 .env 를 자동으로 읽어 들입니다)
const client = new Anthropic();

const OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    reply: { type: "string" },
    tasks: {
      type: "array",
      items: {
        type: "object",
        properties: {
          minutes: { type: "integer" },
          task: { type: "string" },
        },
        required: ["minutes", "task"],
        additionalProperties: false,
      },
    },
    intent: {
      type: "string",
      enum: ["propose", "review", "celebrate", "encourage", "safety"],
    },
  },
  required: ["reply", "tasks", "intent"],
  additionalProperties: false,
};

const MODEL = "claude-haiku-4-5";
const FORMAT = { type: "json_schema", schema: OUTPUT_SCHEMA };

// ── 토큰 어뷰징 방어(상태 불필요) ───────────────────────────────
// 요청 1건의 비용 상한을 결정적으로 고정한다. 외부 저장소 없이 함수 안에서 끝낸다.
const MAX_TURNS = 12;            // messages 배열 길이 상한
const MAX_TEXT = 1000;           // 사용자 텍스트 길이(문자) 상한
const MAX_IMAGE_BYTES = 1_500_000; // 이미지 base64 디코드 기준 ≈1.1MB 원본

// Origin/Referer의 host가 요청 host와 같은지(=내 페이지에서 온 요청인지) 확인한다.
// 도메인을 하드코딩하지 않아 로컬(vercel dev)·배포 모두에서 동작.
// 주의: Origin은 브라우저만 자동으로 붙이므로 단순 스크립트/크로스오리진을 막는다
//       (헤더를 위조하는 결연한 공격자까진 못 막음 — 입력 캡이 그 경우의 천장).
function isSameOrigin(req) {
  const host = req.headers.host;
  if (!host) return false;
  const ref = req.headers.origin || req.headers.referer;
  if (!ref) return false; // 정상 브라우저 POST는 Origin을 항상 포함
  try {
    return new URL(ref).host === host;
  } catch {
    return false;
  }
}

// /api/token 이 발급한 HMAC 서명 토큰을 검증한다(서명+만료만, 저장소 불필요).
// APP_SECRET 미설정이면 토큰 검사를 건너뛴다(Origin·입력 캡 방어는 그대로 유지).
function isValidToken(req) {
  const secret = process.env.APP_SECRET;
  if (!secret) return true;
  const token = req.headers["x-app-token"];
  if (typeof token !== "string") return false;
  const [expStr, sig] = token.split(".");
  const exp = Number(expStr);
  if (!exp || !sig || Date.now() > exp) return false;
  const expected = createHmac("sha256", secret).update(expStr).digest("hex");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

// ── 2단계 체인 프롬프트 ──────────────────────────────────────────
// 팀장(분석·과업)이 초안을 만들고, 상담가(메시지·안전)가 다듬어 최종본을 낸다.

// 1단계 — 팀장: 입력(사진 포함)을 분석해 과업 초안을 만든다.
const LEADER_PROMPT = `[01 ROLE]
너는 고립은둔청년 일상회복 대응팀인 '오늘의 일상 연구팀'의 '발굴 리드'다. 생활코칭·정리 분야 7년차.
팀원(사용자)은 우리 서비스가 도울 '또 다른 고립은둔청년'에게 줄 일상 과업을 발굴하고, 자기가 먼저 직접 해보며 검증하는 발굴팀원이다.
절대 '팀원 자신의 회복'을 목적으로 말하지 않는다 — 늘 "다른 친구(우리 사용자)에게 줄 과업을 함께 발굴·검증한다"는 관점으로 말한다.

[02 TASK]
<input> 안의 팀원 메시지(주변 사진=발굴 후보지가 기본, 설명은 선택)를 분석해, 아래 발굴·검증 사이클의 현재 단계를 판단하고 reply·tasks·intent 초안을 만든다. 최종 말투 다듬기는 다음 단계(상담가)가 한다.

[03 OUTPUT FORMAT]
<output_format>
JSON만 — {"reply": 초안, "tasks": {minutes:1|3|5, task} 배열(새 발굴=1·3·5분 3개 / 고른 뒤 1개 / 그 외 []), "intent": "propose|review|celebrate|encourage|safety"}
</output_format>

[04 RULES]
<rules>
- [사이클] 새 발굴(사진/요청) → intent="propose": 그 현장 사진 기준 1·3·5분 후보 과업 3개(각 {minutes:1|3|5, task}). reply는 "이 현장 기준으로 후보 3개 만들었어, 하나 골라 직접 해보고 검증해줘" 식 — "어디부터 하고 싶어?"가 아니라 "어떤 후보부터 검증해볼래?"로 묻는다.
- [사이클] 「…」 이걸로 할게 → intent="propose": 그 후보 1개만 tasks에 담아 구체화 + "직접 해보고 결과를 사진으로 보고해줘".
- [사이클] 수행 후 결과보고("했어요" 등) → intent="review", tasks=[]: 결과를 가볍게 인정 후 "해봤더니 어때?"로 체험을 묻고, 이어 "이 과업을 다른 친구(우리 사용자)가 했을 때 일상 회복에 도움될 것 같아?"라고 검증을 부탁한다. (난이도·시간은 팀원이 버튼으로 평가하니 굳이 묻지 않아도 됨)
- [사이클] 팀원 메시지가 "검증 결과 —"로 시작(난이도 평가 제출) → intent="celebrate", tasks=[]: 검증 기여를 치하("검증 고마워, 추천 목록에 올릴게")하고, '좀 빡셌어'면 시간을 늘리겠다고·'너무 쉬웠어'면 줄이겠다고 짧게 덧붙인 뒤 또 다른 곳을 발굴하자고 권한다. 팀원 자신을 칭찬하지 말고 '기여'를 인정한다.
- [사이클] "오늘은 여기까지 할게" → intent="encourage", tasks=[]: 더 권하지 말고 기여를 인정하며 마무리(명시적 종료에만).
- [사이클] '여기서 더 해볼래'=그 자리 근처, '다른 것도 해볼래'=다른 구역에서 새 후보 발굴. 사진 없음 → "둘러보고 후보가 될 만한 곳 하나 찍어줄래?".
- [과업] 1분=아주 작은 한 동작, 3분=한 무더기, 5분=한 구역. "방 정리해" 같은 큰일 금지. 시간대마다 후보를 속으로 3개씩 떠올려 가장 정확한 1개를 고른다.
- [말투] 공간·성취를 '네 방 / 너의 회복 / 너 잘했어'로 규정하지 않는다 — 공간=「검증 현장」, 선택=「검증 후보」, 결과=「검증 기여」.
- [확인 필요] 사진에서 확실히 보이지 않는 것은 지어내지 말 것. 모호하면 "사진에 ~가 잘 안 보여, 한 번 더 찍어줄래?"로 확인을 요청한다.
- [안전·최우선] 자해·자살 등 위기 신호 → 발굴 설정 즉시 중단, intent="safety", tasks=[] (다음 단계가 처리).
</rules>`;

// 2단계 — 상담가: 원본 입력 + 팀장 초안으로 다듬고, 위기면 오버라이드한다.
const COUNSELOR_PROMPT = `[01 ROLE]
너는 고립은둔청년 일상회복 대응팀인 '오늘의 일상 연구팀'의 시니어 상담가다(고립·은둔 청년을 10년간 만나옴). 발굴 리드의 초안을 받아 최종본을 만든다.

[02 TASK]
<input> 안의 원본 팀원 입력과 <draft> 안의 리드 초안 JSON을 받아, 아래 규칙대로 reply를 다듬어 최종 JSON을 낸다.

[03 OUTPUT FORMAT]
<output_format>
JSON만 — {"reply": 평문 2~4문장, "tasks": {minutes:1|3|5, task} 배열, "intent": "propose|review|celebrate|encourage|safety"}
</output_format>

[04 RULES]
<rules>
- reply를 동료처럼 짧고 따뜻한 2~4문장으로 다듬는다. 따뜻함은 팀원 '자신 칭찬'이 아니라 '발굴·검증 기여 인정'으로 향한다.
- 가짜 긍정·다그침·마크다운·코드블록·사과·군더더기·긴 설교 제거. 못 해도 비난 말고 더 작게.
- 초안이 팀원을 회복 대상자로 대하는 표현(네 방·너의 회복·"너 잘했어" 같은 개인 성취 칭찬, "하고 싶은 것 골라")을 쓰면, 발굴·검증 프레임("검증할 후보 골라", "검증 고마워", "다른 친구가 했을 때 도움될지")으로 바꾼다.
- 감정을 '데이터'로 환원하지 않는다 — 팀원이 힘듦을 비치면 그 감정부터 진심으로 받아준다.
- [안전·최우선·거부권] <input>에 자해·자살 등 위기 신호가 있으면 모든 설정을 버리고 사람 대 사람으로 응답한다 — intent="safety", tasks=[]. 감정을 깊이 받아주며 "혼자가 아니야, 나는 여기 있어"를 전하고, reply에 자살예방상담전화 109(24시간)를 반드시 직접 안내한다.
- 위기가 아니면 tasks·intent는 리드 값을 유지하고 reply만 다듬는다.
</rules>`;

// 응답에서 구조화 JSON 텍스트 한 덩어리를 꺼낸다.
function pickJson(response) {
  return response.content.find((b) => b.type === "text")?.text ?? "{}";
}

// 2단계 체인: 팀장 → 상담가 두 번의 호출.
async function runChain(apiMessages, originalText) {
  // 1단계 — 팀장(사진 포함 분석)
  const draftRes = await client.messages.create({
    model: MODEL,
    max_tokens: 1024,
    system: LEADER_PROMPT,
    messages: apiMessages,
    output_config: { format: FORMAT },
  });
  const draft = pickJson(draftRes);

  // 2단계 — 상담가(원본 입력 + 초안으로 다듬기·안전 오버라이드)
  const reviewRes = await client.messages.create({
    model: MODEL,
    max_tokens: 1024,
    system: COUNSELOR_PROMPT,
    messages: [
      {
        role: "user",
        content: `<input>${originalText || "(사진만 보냈어요)"}</input>\n<draft>${draft}</draft>`,
      },
    ],
    output_config: { format: FORMAT },
  });
  return pickJson(reviewRes);
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  // [방어] 내 페이지에서 온 요청만 허용 — 봇의 직접 API 호출 차단.
  if (!isSameOrigin(req)) {
    res.status(403).json({ error: "허용되지 않은 요청이에요." });
    return;
  }

  // [방어] HMAC 서명 토큰 검증 — 페이지에서 발급받지 않은 요청 차단.
  if (!isValidToken(req)) {
    res.status(403).json({ error: "세션이 만료됐어요. 새로고침해줄래?" });
    return;
  }

  try {
    const { messages, image } = req.body ?? {};
    if (!Array.isArray(messages) || messages.length === 0) {
      res.status(400).json({ error: "messages 배열이 필요합니다." });
      return;
    }

    // [방어] 입력 크기 캡 — 요청당 토큰 비용의 천장을 고정한다.
    if (messages.length > MAX_TURNS) {
      res.status(400).json({ error: "대화가 너무 길어요. 새로 시작해줄래?" });
      return;
    }
    const lastMsg = messages[messages.length - 1];
    if (typeof lastMsg?.content === "string" && lastMsg.content.length > MAX_TEXT) {
      res.status(400).json({ error: "메시지가 너무 길어요. 조금 줄여줄래?" });
      return;
    }
    if (image?.data && (image.data.length * 3) / 4 > MAX_IMAGE_BYTES) {
      res.status(413).json({ error: "사진이 너무 커요. 다시 찍어줄래?" });
      return;
    }

    // 이미지가 있으면 현재(마지막) 사용자 메시지에 image 블록으로 붙인다.
    // (과거 턴 이미지는 보존하지 않아 토큰을 아낀다 — 직전 사진만 분석)
    let apiMessages = messages;
    if (image && image.data && messages.length) {
      const last = messages[messages.length - 1];
      const text = typeof last.content === "string" ? last.content : "";
      apiMessages = [
        ...messages.slice(0, -1),
        {
          role: last.role,
          content: [
            {
              type: "image",
              source: {
                type: "base64",
                media_type: image.mediaType || "image/jpeg",
                data: image.data,
              },
            },
            ...(text ? [{ type: "text", text }] : []),
          ],
        },
      ];
    }

    // 안전 오버라이드가 원본을 보도록, 직전 사용자 텍스트를 체인 2단계에 넘긴다.
    const lastUser = messages[messages.length - 1];
    const originalText =
      typeof lastUser?.content === "string" ? lastUser.content : "";

    const jsonText = await runChain(apiMessages, originalText);
    const result = JSON.parse(jsonText);

    // 난이도 평가 제출('검증 결과 — …')은 검증 완료로 확정한다.
    // 모델의 intent 분류가 흔들려도 UI 루프(카운트+1, 다음 발굴 카드)가 멈추지 않도록 서버에서 못박음.
    if (typeof originalText === "string" && originalText.startsWith("검증 결과 —")) {
      result.intent = "celebrate";
      result.tasks = [];
    }

    res.status(200).json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "연결이 늦어지고 있는것 같아요. 나중에 다시 보내주세요." });
  }
}
