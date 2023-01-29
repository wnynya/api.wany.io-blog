import { console } from '@wnynya/logger';

import express from 'express';
const router = express.Router();

import auth, {
  MySQLAuthElement,
  MySQLAuthPermissions,
  MySQLAuthAccount,
  MySQLAuthSession,
  MySQLAuthKey,
} from '@wnynya/auth';

import middlewares from '@wnynya/express-middlewares';
//const internal = middlewares.check.internal;
const internal = () => {
  return (req, res, next) => {
    next();
  };
};
const login = middlewares.check.login;
const body = middlewares.check.body;
const perm = middlewares.check.perm;
const others = (perm) => {
  return (req, res, next) => {
    if (req.account.uid != req.p.account.element.uid) {
      if (!req.hasPermission(perm)) {
        res.error('permission403');
        return;
      }
    }
    next();
  };
};

import VerifyEmail from '../modules/auth/verify-email.mjs';

const logprefix = '[Auth]: ';

/**
 * 계정 관련 작업은 모든 CORS 요청 차단
 *
 * 권한 필요 없음:
 *   계정 생성 (이메일 인증번호 확인 필요)
 *   세션 생성 (로그인)
 *   인증번호 전송 (이메일/계정 생성)
 *   인증번호 확인 (이메일/계정 생성)
 *   계정 비밀번호 변경 (이메일 인증번호 확인 필요)
 *   인증번호 전송 (이메일/계정 비밀번호 변경)
 *   인증번호 확인 (이메일/계정 비밀번호 변경)
 *
 * 기본 생성된 계정에 자동으로 부여되는 권한:
 * (현재 계정에 대한 접근만 가능, 키에 권한 부여 불가)
 *   계정 정보
 *   계정 수정
 *   계정 제거 (이메일 인증번호 확인 필요)
 *   계정 이메일 변경 (이메일 인증번호 확인 필요)
 *   인증번호 전송 (이메일/계정 이메일 변경)
 *   인증번호 확인 (이메일/계정 이메일 변경)
 *   계정 비밀번호 변경 (기존 비밀번호 인증 필요)
 *   세션 목록
 *   모든 세션 제거 (전체 로그아웃)
 *   세션 정보
 *   세션 제거 (로그아웃)
 *   권한 목록
 *   키 목록
 *   키 생성
 *   키 수정
 *   키 제거
 *   키 권한 목록
 *   키 권한 추가
 *   키 권한 제거
 *
 * 추가 부여가 필요한 권한:
 * (모든 계정에 접근 가능)
 *   계정 목록
 *     auth.accounts.get
 *   계정 정보
 *     auth.accounts.account.get
 *   계정 수정
 *     auth.accounts.account.patch
 *   계정 제거
 *     auth.accounts.account.delete
 *   계정 이메일 변경 (이메일 인증번호 확인 필요)
 *     auth.accounts.account.email.patch
 *   계정 이메일 변경 (강제)
 *     auth.accounts.account.email.force.patch
 *   계정 비밀번호 변경 (기존 비밀번호 인증 필요)
 *     auth.accounts.account.password.patch
 *   계정 비밀번호 변경 (강제)
 *     auth.accounts.account.password.force.patch
 *   세션 목록
 *     auth.accounts.account.sessions.get
 *   모든 세션 제거 (전체 로그아웃)
 *     auth.accounts.account.sessions.delete
 *   세션 정보
 *     auth.accounts.account.sessions.session.get
 *   세션 제거 (로그아웃)
 *     auth.accounts.account.sessions.session.delete
 *   권한 목록
 *     auth.accounts.account.permissions.get
 *   권한 추가
 *     auth.accounts.account.permissions.put
 *   권한 제거
 *     auth.accounts.account.permissions.delete
 *   키 목록
 *     auth.accounts.account.keys.get
 *   키 생성
 *     auth.accounts.account.keys.post
 *   키 수정
 *     auth.accounts.account.keys.key.patch
 *   키 제거
 *    auth.accounts.account.keys.key.delete
 *   키 권한 목록
 *     auth.accounts.account.keys.key.permissions.get
 *   키 권한 추가
 *     auth.accounts.account.keys.key.permissions.put
 *   키 권한 제거
 *     auth.accounts.account.keys.key.permissions.delete
 */

/**
 * @desc 계정 목록
 * @permission auth.accounts.get
 */
router.get(
  '/accounts',
  internal(),
  login(),
  perm('auth.accounts.get'),
  (req, res) => {
    MySQLAuthAccount.index(
      req.query.search,
      req.query.size,
      req.query.page,
      req.query.count == 'true',
      true
    )
      .then(res.data)
      .catch(res.error);
  }
);

/**
 * @desc 계정 생성
 */
router.post('/accounts', internal(), login(false), body(), (req, res) => {
  // 세션에 저장된 이메일 인증 정보 확인
  const verification = req.session.verification;
  if (
    !verification ||
    verification.type != 'register' ||
    !verification.verified
  ) {
    res.error('auth401');
    return;
  }
  const email = verification.email;

  // 정상적인 사용자 ID 인지 확인
  let eid = req.body.eid;
  if (eid.match(/[^a-z0._+\-]/)) {
    res.error('account409-1-05');
    return;
  }
  if (eid.length < 4) {
    res.error('account409-1-03');
    return;
  }

  // 이미 사용 중인 사용자 ID 인지 확인
  MySQLAuthAccount.of(eid)
    .then(() => {
      res.error('account409');
    })
    .catch(() => {
      // 이미 사용 중인 사용자 이메일인지 확인
      MySQLAuthAccount.of(email)
        .then(() => {
          res.error('account409');
        })
        .catch(() => {
          // 새로운 계정 생성
          const account = new MySQLAuthAccount(MySQLAuthElement());
          account.eid = eid;
          account.email = email;
          account.element.label = eid; // 사용자 이름에 임시로 사용자 ID 입력
          account
            .insert(req.body.password)
            .then(() => {
              // 세션에 저장된 이메일 인증 정보 제거
              delete req.session.verification;
              // 생성된 계정으로 로그인
              req.session.save(0, account);
              res.ok();
            })
            .catch(res.error);
        });
    });
});

/**
 * @desc 인증번호 전송 (이메일/계정 생성)
 */
router.post(
  '/verification/email/register/send',
  internal(),
  body(),
  (req, res) => {
    const email = req.body.email;

    // 정상적인 이메일 주소인지 확인
    if (!email || !email.match(/^.+@.+\.[^.]+$/)) {
      res.error('default400');
      return;
    }

    // 이미 사용 중인 이메일인지 확인
    MySQLAuthAccount.of(email)
      .then(() => {
        res.error('default409');
        return;
      })
      .catch(() => {
        // 인증번호 전송
        VerifyEmail.send(email, 'register')
          .then((code) => {
            // 세션에 인증 정보 저장
            req.session.verification = {
              email: email,
              type: 'register',
              code: code,
            };
            req.session.save();
            res.ok();
          })
          .catch(res.error);
      });
  }
);

/**
 * @desc 인증번호 확인 (이메일/계정 생성)
 */
router.post(
  '/verification/email/register/verify',
  internal(),
  body(),
  (req, res) => {
    const email = req.body.email;
    const code = req.body.code;

    // 세션에 저장된 인증 정보가 있는지 확인
    if (!req.session.verification) {
      res.error('auth401');
      return;
    }

    // 인증 정보가 일치하는지 확인
    const verification = req.session.verification;
    if (
      verification.email == email &&
      verification.type == type &&
      verification.code == code
    ) {
      // 세션에 인증 정보 확인 여부 추가
      req.session.verification.verified = true;
      req.session.save();
      res.ok();
    } else {
      res.error('auth401');
    }
  }
);

/**
 * @desc 계정 비밀번호 변경 (이메일 인증번호 확인 필요)
 */
router.post('/accounts/change-password', internal(), body(), (req, res) => {});

/**
 * @desc 인증번호 전송 (이메일/계정 비밀번호 변경)
 */
router.post(
  '/verification/email/change-password/send',
  internal(),
  body(),
  (req, res) => {
    const aid = req.body.aid;
    const email = req.body.email;

    // 계정 확인
    MySQLAuthAccount.of(aid)
      .then((account) => {
        // 계정 이메일 정보가 일치하는지 확인
        if (account.email != email) {
          res.error('default409');
          return;
        }
        // 인증번호 전송
        VerifyEmail.send(account.email, 'change-password')
          .then((code) => {
            // 세션에 인증 정보 저장
            req.session.verification = {
              email: account.email,
              type: 'change-password',
              code: code,
            };
            req.session.save();
            res.ok();
          })
          .catch(res.error);
      })
      .catch(() => {
        res.error('default409');
        return;
      });
  }
);

/**
 * @desc 인증번호 확인 (이메일/계정 비밀번호 변경)
 */
router.post(
  '/verification/email/change-password/verify',
  internal(),
  body(),
  (req, res) => {
    const email = req.body.email;
    const code = req.body.code;

    // 세션에 저장된 인증 정보가 있는지 확인
    if (!req.session.verification) {
      res.error('auth401');
      return;
    }

    // 인증 정보가 일치하는지 확인
    const verification = req.session.verification;
    if (
      verification.email == email &&
      verification.type == type &&
      verification.code == code
    ) {
      // 세션에 인증 정보 확인 여부 추가
      req.session.verification.verified = true;
      req.session.save();
      res.ok();
    } else {
      res.error('auth401');
    }
  }
);

/* 계정 정보 필요 (req.p.account) */
router.all('/accounts/:aid*', internal(), (req, res, next) => {
  // Preflight 요청 처리
  if (req.method == 'OPTIONS') {
    next();
    return;
  }
  let aid = req.params.aid;
  // aid 가 @me 인 경우 현재 로그인된 계정을 가리킴
  if (aid == '@me') {
    aid = req.login ? req.account.uid : '';
  }
  // 계정 정보 불러오기
  MySQLAuthAccount.of(aid)
    .then((account) => {
      req.p.account = account;
      next();
    })
    .catch(res.error);
});

/**
 * @desc 계정 정보
 * @permission others: auth.accounts.account.get
 */
router.get(
  '/accounts/:aid',
  internal(),
  login(),
  others('auth.accounts.account.get'),
  (req, res) => {
    res.data(req.p.account.toJSON());
  }
);

/**
 * @todo
 * @desc 계정 수정
 * @permission others: auth.accounts.account.patch
 * 바꿀 수 있을 법한 게 eid, label, phone 밖에 없는 듯...
 */
router.patch(
  '/accounts/:aid',
  internal(),
  login(),
  others('auth.accounts.account.patch'),
  (req, res) => {}
);

/**
 * @todo
 * @desc 계정 제거
 * @permission others: auth.accounts.account.delete
 */
router.delete(
  '/accounts/:aid',
  internal(),
  login(),
  others('auth.accounts.account.delete'),
  (req, res) => {}
);

/**
 * @todo
 * @desc 계정 비밀번호 변경 (기존 비밀번호 인증 필요)
 * @permission others: auth.accounts.account.password.patch
 */
router.patch(
  '/accounts/:aid/password',
  internal(),
  login(),
  others('auth.accounts.account.password.patch'),
  body(),
  (req, res) => {
    const password = req.body.password;
    const newpassword = req.body.newpassword;

    // 기존 비밀번호 확인
    if (req.p.account.verify(password)) {
      // 새로운 비밀번호로 변경
      req.p.account.updatePassword(newpassword).then(res.ok).catch(res.error);
    } else {
      res.error('auth401');
      return;
    }
  }
);

/**
 * @todo
 * @desc 계정 비밀번호 변경 (강제)
 * @permission auth.accounts.account.password.force.patch
 */
router.patch(
  '/accounts/:aid/password/force',
  internal(),
  login(),
  perm('auth.accounts.account.password.force.patch'),
  body(),
  (req, res) => {
    const newpassword = req.body.newpassword;

    // 새로운 비밀번호로 변경
    req.p.account.updatePassword(newpassword).then(res.ok).catch(res.error);
  }
);

/**
 * @desc 세션 목록
 * @permission others: auth.accounts.account.sessions.get
 */
router.get(
  '/accounts/:aid/sessions',
  internal(),
  login(),
  others('auth.accounts.account.sessions.get'),
  (req, res) => {
    req.p.account.selectSessions(true).then(res.data).catch(res.error);
  }
);

/**
 * @desc 세션 생성 (로그인)
 */
router.post(
  '/accounts/:aid/sessions',
  internal(),
  login(false),
  body(),
  (req, res) => {
    setTimeout(() => {
      // 비밀번호 확인
      if (req.p.account.verify(req.body.password)) {
        // 세션에 로그인 정보 저장
        req.session.save(
          req.body.keep ? 1000 * 60 * 60 * 24 * 365 : 0,
          req.p.account
        );
        res.ok();
      } else {
        res.error('auth401');
        return;
      }
    }, Math.floor(500 + Math.random() * 1500)); // 랜덤 시간 지연
  }
);

/**
 * @desc 모든 세션 제거 (전체 로그아웃)
 * @permission others: auth.accounts.account.sessions.delete
 */
router.delete(
  '/accounts/:aid/sessions',
  internal(),
  login(),
  others('auth.accounts.account.sessions.delete'),
  (req, res) => {
    req.p.account.clearSessions().then(res.ok).catch(res.error);
  }
);

/* 세션 정보 필요 (req.p.session) */
router.all('/accounts/:aid/sessions/:sid*', internal(), (req, res, next) => {
  // Preflight 요청 처리
  if (req.method == 'OPTIONS') {
    next();
    return;
  }
  let sid = req.params.sid;
  // sid 가 @current 인 경우 현재 세션을 가리킴
  if (sid == '@current') {
    sid = req.session.id;
  }
  // 계정의 세션이 맞는지 확인
  req.p.account
    .selectSessions()
    .then((sessions) => {
      let sess;
      for (const session of sessions) {
        if (session.sid == sid) {
          sess = session;
          break;
        }
      }
      if (!sess) {
        res.error('session404');
        return;
      }
      req.p.session = sess;
      next();
    })
    .catch(res.error);
});

/**
 * @desc 세션 정보
 * @permission others: auth.accounts.account.sessions.session.get
 */
router.get(
  '/accounts/:aid/sessions/:sid',
  internal(),
  login(),
  others('auth.accounts.account.sessions.session.get'),
  (req, res) => {
    res.data(req.p.session.toJSON());
  }
);

/**
 * @desc 세션 제거 (로그아웃)
 * @permission others: auth.accounts.account.sessions.session.delete
 */
router.delete('/accounts/:aid/sessions/:sid', (req, res) => {
  req.p.session
    .delete()
    .then(() => {
      req.session.destroy();

      res.ok();
    })
    .catch(res.error);
});

/**
 * @desc 권한 목록
 * @permission others: auth.accounts.account.permissions.get
 */
router.get(
  '/accounts/:aid/permissions',
  internal(),
  login(),
  others('auth.accounts.account.permissions.get'),
  (req, res) => {
    res.data(req.p.account.element.permissions.array);
  }
);

/**
 * @desc 권한 추가
 * @permission auth.accounts.account.permissions.put
 */
router.put(
  '/accounts/:aid/permissions',
  internal(),
  login(),
  perm('auth.accounts.account.permissions.put'),
  (req, res) => {
    // 계정 권한 추가
    req.p.account.element.permissions.add(req.body.permissions);
    // 권한 정보 업데이트
    req.p.account.element.permissions
      .update()
      .then(() => {
        res.ok();
      })
      .catch(res.error);
  }
);

/**
 * @desc 권한 제거
 * @permission auth.accounts.account.permissions.delete
 */
router.delete(
  '/accounts/:aid/permissions',
  internal(),
  login(),
  perm('auth.accounts.account.permissions.delete'),
  (req, res) => {
    // 계정 권한 제거
    req.p.account.element.permissions.del(req.body.permissions);
    // 권한 정보 업데이트
    req.p.account.element.permissions
      .update()
      .then(() => {
        res.ok();
      })
      .catch(res.error);
  }
);

/**
 * @desc 키 목록
 * @permission others: auth.accounts.account.keys.get
 */
router.get(
  '/accounts/:aid/keys',
  internal(),
  login(),
  others('auth.accounts.account.keys.get'),
  (req, res) => {
    req.p.account.getKeys(true).then(res.data).catch(res.error);
  }
);

/**
 * @desc 키 생성
 * @permission others: auth.accounts.account.keys.post
 */
router.post(
  '/accounts/:aid/keys',
  internal(),
  login(),
  others('auth.accounts.account.keys.post'),
  (req, res) => {
    req.p.account
      .insertKey()
      .then((key) => {
        res.data(key.element.uid);
      })
      .catch(res.error);
  }
);

/* 키 정보 필요 (req.p.key) */
router.all('/accounts/:aid/keys/:kid*', internal(), (req, res, next) => {
  // Preflight 요청 처리
  if (req.method == 'OPTIONS') {
    next();
    return;
  }
  let kid = req.params.kid;
  // 계정의 키가 맞는지 확인
  req.p.account
    .selectKey()
    .then((keys) => {
      let ky;
      for (const key of keys) {
        if (key.element.uid == kid) {
          ky = key;
          break;
        }
      }
      if (!ky) {
        res.error('key404');
        return;
      }
      req.p.key = ky;
      next();
    })
    .catch(res.error);
});

/**
 * @desc 키 정보
 * @permission others: auth.accounts.account.keys.key.get
 */
router.get(
  '/accounts/:aid/keys/:kid',
  internal(),
  login(),
  others('auth.accounts.account.keys.key.get'),
  (req, res) => {
    res.data(req.p.key.toJSON());
  }
);

/**
 * @desc 키 수정
 * @permission others: auth.accounts.account.keys.key.patch
 */
router.patch(
  '/accounts/:aid/keys/:kid',
  internal(),
  login(),
  others('auth.accounts.account.keys.key.patch'),
  body(),
  (req, res) => {
    const label = req.body.label
      ? req.body.label
      : 'A Key of ' + req.p.account.element.label;

    req.p.key.element.label = label;
    req.p.key.element.update(['label']).then(res.ok).catch(res.error);
  }
);

/**
 * @desc 키 제거
 * @permission others: auth.accounts.account.keys.key.delete
 */
router.delete(
  '/accounts/:aid/keys/:kid',
  internal(),
  login(),
  others('auth.accounts.account.keys.key.delete'),
  (req, res) => {
    req.p.key.delete().then(res.ok).catch(res.error);
  }
);

/**
 * @desc 키 권한 목록
 * @permission others: auth.accounts.account.keys.key.permissions.get
 */
router.get(
  '/accounts/:aid/keys/:kid/permissions',
  internal(),
  login(),
  others('auth.accounts.account.keys.key.permissions.get'),
  (req, res) => {
    res.data(req.p.key.element.permissions.array);
  }
);

/**
 * @desc 키 권한 추가
 * @permission others: auth.accounts.account.keys.key.permissions.put
 */
router.put(
  '/accounts/:aid/keys/:kid/permissions',
  internal(),
  login(),
  others('auth.accounts.account.keys.key.permissions.put'),
  body(),
  (req, res) => {
    // 키 권한 추가
    req.p.key.element.permissions.add(req.body.permissions);
    // 키 권한 정보 업데이트
    req.p.key.element.permissions
      .update()
      .then(() => {
        res.ok();
      })
      .catch(res.error);
  }
);

/**
 * @desc 키 권한 제거
 * @permission others: auth.accounts.account.keys.key.permissions.delete
 */
router.delete(
  '/accounts/:aid/keys/:kid/permissions',
  internal(),
  login(),
  others('auth.accounts.account.keys.key.permissions.delete'),
  body(),
  (req, res) => {
    // 키 권한 제거
    req.p.key.element.permissions.del(req.body.permissions);
    // 키 권한 정보 업데이트
    req.p.key.element.permissions
      .update()
      .then(() => {
        res.ok();
      })
      .catch(res.error);
  }
);

export default router;
