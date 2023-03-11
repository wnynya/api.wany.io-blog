import express from 'express';
const router = express.Router();

import { BlogArticle, BlogComment } from '@wnynya/blog';

import middlewares from '@wnynya/express-middlewares';
const internal = middlewares.check.internal;
const login = middlewares.check.login;
const body = middlewares.check.body;
const perm = middlewares.check.perm;
const others = (perm) => {
  return (req, res, next) => {
    if (req.account.uid != req.p.article.author.element.uid) {
      if (!req.hasPermission(perm)) {
        res.error('permission403');
        return;
      }
    }
    next();
  };
};

const logprefix = '[Blog]: ';

router.get('/', (req, res) => {
  res.ok('Wanyne API / Blog');
});

/**
 * @desc 게시글 목록
 * @permission external: blog.articles.get
 */
router.get('/articles', internal('blog.articles.get'), (req, res) => {
  BlogArticle.index(
    {},
    req.query.size,
    req.query.page,
    req.query.count == 'true',
    true
  )
    .then(res.data)
    .catch(res.error);
});

/**
 * @desc 게시글 작성
 */
router.post(
  '/articles',
  internal(),
  login(),
  perm('blog.articles.post'),
  body(),
  (req, res) => {
    let eid = req.body.eid;
    BlogArticle.of(eid)
      .then(() => {
        res.error('이미 존재하는 게시글 ID입니다.', 409);
      })
      .catch(() => {
        const article = new BlogArticle();
        article.eid = eid;
        article.title = req.body.title || '제목없음';
        article.thumbnail = req.body.thumbnail || '';
        article.content = req.body.content || '<p>내용없음</p>';
        req.account.element = { uid: req.account.uid };
        article.author = req.account;
        article.category = req.body.category || 'default';
        article.creation = req.body.creation
          ? new Date(req.body.creation)
          : new Date();
        article
          .insert()
          .then(() => {
            res.data(article.eid);
          })
          .catch(res.error);
      });
  }
);

/* 게시글 정보 필요 (req.p.article) */
router.all('/articles/:aid*', internal(), (req, res, next) => {
  // Preflight 요청 처리
  if (req.method == 'OPTIONS') {
    next();
    return;
  }
  let aid = req.params.aid;
  // 게시글 정보 불러오기
  BlogArticle.of(aid)
    .then((article) => {
      req.p.article = article;
      next();
    })
    .catch(() => {
      res.error('default404');
    });
});

/**
 * @desc 게시글 정보
 * @permission external: blog.articles.article.get
 */
router.get(
  '/articles/:aid',
  internal('blog.articles.article.get'),
  login(),
  (req, res) => {
    const obj = req.p.article.toJSON();
    obj.creation2 = new Date(obj.creation).toJSON();
    res.data(obj);
  }
);

/**
 * @todo
 * @desc 게시글 수정
 * @permission others: blog.articles.article.patch
 */
router.patch(
  '/articles/:aid',
  internal(),
  login(),
  others('blog.articles.article.patch'),
  body(),
  (req, res) => {
    let eid = req.body.eid;
    BlogArticle.of(eid != req.p.article.eid ? eid : null)
      .then(() => {
        res.error('이미 존재하는 게시글 ID입니다.', 409);
      })
      .catch(() => {
        const article = req.p.article;
        article.eid = eid;
        article.title = req.body.title || '제목없음';
        article.thumbnail = req.body.thumbnail || '';
        article.content = req.body.content || '<p>내용없음</p>';
        article.category = req.body.category || 'default';
        article.creation = new Date(req.body.creation);
        article.modified = new Date();
        article
          .update([
            'eid',
            'title',
            'thumbnail',
            'content',
            'category',
            'creation',
            'modified',
          ])
          .then(() => {
            res.data(article.eid);
          })
          .catch(res.error);
      });
  }
);

/**
 * @todo
 * @desc 게시글 제거
 * @permission others: blog.articles.article.delete
 */
router.delete(
  '/articles/:aid',
  internal(),
  login(),
  others('blog.articles.article.delete'),
  (req, res) => {
    req.p.article.delete().then(res.ok).catch(res.error);
  }
);

export default router;
