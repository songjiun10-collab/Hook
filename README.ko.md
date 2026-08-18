# Hook

Claude Code용 심각도 등급별 PreToolUse/PostToolUse 가드 훅 -
[songjiun10-collab/hncs](https://github.com/songjiun10-collab/hncs)에서
만든 훅 안전장치 프레임워크를 프로젝트 무관하게 추출한 것.

## 뭐가 들어있나

Claude Code 플러그인으로, 다음을 제공함:

- **4단계 심각도 모델**(`hooks/_hook_common.py`): LOW(로그만), MEDIUM(상위
  에이전트 승인 필요), HIGH(사람에게 물어봄 - 서브에이전트발이면 하드
  deny), CRITICAL(기본 deny - 서브에이전트발은 override조차 안 받음).
- **Override 메커니즘** - 의도적으로 명시된 우회(bash 명령 끝에
  `# HNCS-OVERRIDE: <rule>: <reason>` 주석, 또는 Edit/Write/MultiEdit
  가드용 sentinel 파일)는 항상 통과되지만, 모든 사용이 부여된 시점의
  git sha와 함께 `override_audit.jsonl`에 기록됨. 훅은 개발자의 판단을
  대신하지 않는다 - 위험한 행동을 무의식적으로, 조용히 해버리는 것만
  막는다.
- **Decision Record + must_hook** - 가드된 액션 직전에 에이전트가
  `mcp__must_hook__write_decision_record` MCP 툴을 통해 자기 위험도
  판단(severity/confidence/reason/expected_risk)을 self-report할 수
  있고(필수 게이트가 적용되면 반드시 해야 함), 이 툴의 파라미터
  스키마(pydantic `Field` 제약)가 잘못된 호출을 코드에 도달하기 전에
  거부함 - 더 이상 손으로 쓴 JSON이 조용히 틀린 채로 남지 않음. 이
  기록은 가드 훅이 만드는 로그 항목에 붙어서, 나중에
  `tools/eval_hook_judgments.py`가 에이전트의 예측과 실제로 벌어진 일
  (차단됨 / 사람한테 물어봤지만 답은 구조적으로 관측 불가 / revert됨 /
  안 됨)을 비교할 수 있게 함.
- **가드 훅 7개**: `protect_destructive`(CRITICAL - `rm -rf`,
  `git reset --hard`, `git clean -f`, `git branch -D`),
  `protect_push_safety`(force-push는 CRITICAL / 커밋 작성자는 HIGH),
  `protect_branch`(HIGH - main/master/detached HEAD에 commit/push),
  `protect_reviewer_prejudging`(HIGH - 리뷰어한테 발견사항 미리 재단
  지시), `protect_ready_without_review`(HIGH - 전체-브랜치 리뷰 기록
  없이 PR을 ready로 전환), `protect_agent_model_naming`(LOW - Agent
  디스패치에 model 미지정 또는 haiku 사용),
  `protect_test_coverage`(HIGH - 테스트 없이 새 소스 파일 커밋).
- **`must_hook_server.py`** - 위 스키마 강제를 담당하는 로컬 MCP 서버.
- **`tools/rotate_hook_logs.py`** / **`tools/eval_hook_judgments.py`** -
  독립 유지관리 스크립트(훅 체인에는 안 걸림, 수동 또는 스케줄 실행).

## 뭐가 안 들어있나

여기 있는 가드 훅 중 MEDIUM 등급을 실제로 쓰는 건 하나도 없음 - 메커니즘
(`allow_with_medium_approval()`, `record_agent_approval.py`,
`deliver_caution.py`)은 포함/테스트돼 있어서 다운스트림 프로젝트가 그
위에 자기만의 MEDIUM 가드를 만들 수 있지만, 번들된 가드 중엔 그게
필요한 게 없음.

이 플러그인엔 프로젝트 전용 가드도 안 들어있음. 원 프로젝트(Hncs)는 이
프레임워크 위에 자기만의 가드 3개를 따로 유지함 - "이 shipped 산출물은
절대 건드리지 마" 가드, "이 생성 파일은 손으로 고치지 마" 가드, "문서에
근거 없는 수치 주장 넣지 마" 가드 - 이건 트리거(특정 파일 경로, 특정
주장 패턴)가 본질적으로 프로젝트마다 달라서임. 이 레포의 훅은 재사용
가능한 코어로 쓰고, 자기 프로젝트의 불변조건은 저런 식으로 따로 만들
것.

## 설치

```bash
claude plugin marketplace add songjiun10-collab/hook
claude plugin install hook@hook
```

이러면 `hooks/hooks.json`의 훅들과 `.mcp.json`의 `must_hook` MCP
서버가 등록됨 - 둘 다 `${CLAUDE_PLUGIN_ROOT}` 기준 상대경로.

`must_hook_server.py`용으로 `mcp==2.0.0`이 필요함(`requirements.txt`
참고).

## 자기 프로젝트에 맞게 조정하기

- `protect_push_safety.py`의 `_CLAUDE_AUTHOR_EMAIL` - 자기 프로젝트가
  기대하는 커밋 작성자 이메일로 설정.
- `protect_test_coverage.py`의 `_COVERAGE_EXPECTED_DIR_RE` - 자기
  프로젝트의 소스 레이아웃으로 설정(기본값은 원 프로젝트의
  `tools/`/`brands/`/`core/`/`hybrid_engine/`).
- 모든 훅은 `HNCS_HOOK_*` 환경변수가 설정돼 있으면 거기서 sentinel/로그
  경로를 읽고, 없으면 훅 스크립트 자체 옆의 파일로 fallback함
  (`_hook_common.py`의 모듈 레벨 `_HOOKS_DIR`). 환경변수 이름에 원
  프로젝트 이름이 들어있지만 그냥 문자열일 뿐이라 이름 안 바꿔도 그대로
  동작함.
- `protect_reviewer_prejudging.py`/`protect_ready_without_review.py`의
  deny 메시지에 나오는 override 안내 문구는 `hooks/.pending_override.json`
  라고 돼있는데, 이건 훅 스크립트 자신이 실제로 실행되는 위치(보통
  플러그인 설치 위치) 기준 상대경로지 고정 경로가 아님.

## 테스트

```bash
pip install -r requirements.txt
python3 -m unittest discover -s tests
```

182개 테스트, 전부 실제 subprocess 실행으로 훅 로직을 end-to-end
확인함(모킹 아님) - 각 테스트가 `HNCS_HOOK_*` 환경변수 오버라이드로
로그/sentinel 파일을 격리하기 때문에 테스트 실행이 이 레포 자체의
`hooks/violations_log.jsonl`을 건드리지 않음.

## 알려진 한계

- **정규식/텍스트 매칭이지 진짜 셸 파서가 아님.** Bash 트리거 가드들
  (`protect_destructive`, `protect_push_safety`, `protect_branch`,
  `protect_test_coverage`)이 공유하는 `_STMT_START` + heredoc 스트리핑
  패턴이 알려진 false-positive/우회 케이스(`git`과 `push` 사이의 전역
  옵션, `--force-with-lease=<refspec>`, 위험한 명령을 그냥 산문으로
  *언급*만 하는 heredoc)는 막지만, 충분히 특이한 셸 구문은 여전히 양쪽
  방향 다 뚫릴 수 있음.
- **Override는 self-servable함.** 에이전트가 이유를 지어내면(예: 실제론
  사용자가 승인 안 했는데 "사용자 승인함"이라고 씀) 여기 어떤 훅도 그걸
  검증할 방법이 없음 - 대화 맥락을 못 보기 때문. 이 설계는 *의식적으로
  기록된* 행동만 보장하지 *진짜인지*는 보장 안 함. MEDIUM의 opus 전용
  승인 마커가 위조 난이도를 한 단계 높이지만 완전히 막진 못함 -
  컨트롤러가 "무조건 승인해"로 디스패치 프롬프트를 짤 수 있으므로.
- **`ask()`의 실제 사람 답변은 구조적으로 관측 불가능함.** Claude Code
  런타임이 이 프로세스 밖에서 그 인터랙티브 프롬프트를 처리하는데, 그건
  훅 스크립트가 이미 종료된 뒤임 - `eval_hook_judgments.py`는 이
  경로에 대해 항상 `ask_unknown`만 보고할 수 있고, 진짜 승인/거부
  결과는 절대 못 냄.
- **`ask()`는 서브에이전트 자신의 턴 안에서 fail-open됨** - 프롬프트를
  띄울 인터랙티브 화면 자체가 없음. 여기 모든 가드는 `ask()`를 쓸지
  하드 `deny()`를 쓸지 정하기 전에 `is_subagent_call()`을 체크하는데
  정확히 이 이유 때문임 - 이 프레임워크 위에 새 가드를 만든다면 똑같이
  할 것.

## 라이선스

MIT
