
import sys

import urlparse
from urllib import quote_plus
import urllib2
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers

import oauth2 as oauth
from tornado import web,ioloop

isDev = True
subdomain = 'sandbox' if isDev else 'www'
request_token_url = 'https://%s.ponoko.com/oauth/request_token'%(subdomain)
access_token_url = 'https://%s.ponoko.com/oauth/access_token'%(subdomain)
authorize_url = 'https://%s.ponoko.com/oauth/authorize'%(subdomain)
UPLOAD_URL = 'https://sandbox.ponoko.com/services/api/v2/products'

CONSUMER_KEY = '<CONSUMER_KEY_FROM_PONOKO_APP_PAGE>'
CONSUMER_SECRET = '<CONSUMER_SECRET_FROM_PONOKO_APP_PAGE>'
callback_url = '<fill-in-your-callback-url-here>'

class RequestTokenFetcher(web.RequestHandler):
  def get(self):
    try:
      consumer = oauth.Consumer(CONSUMER_KEY, CONSUMER_SECRET)
      client = oauth.Client(consumer) 

      url = '%s?oauth_callback=%s'%(request_token_url, quote_plus(callback_url))
      resp, content = client.request(url, "GET")
      if resp['status'] != '200':
        print 'Ponoko Request Token failure',str(resp)
        raise web.HTTPError(500)
        return

      request_token = dict(urlparse.parse_qsl(content))
      self.set_secure_cookie("_ponokoauth_",
        str(request_token['oauth_token_secret']))

      url = "%s?oauth_token=%s" % (authorize_url, request_token['oauth_token'])

      self.redirect(url)
    except Exception, e:
      print e

class AccessTokenFetcher(web.RequestHandler):
  def get(self):
    try:
      oauth_token = self.get_argument('oauth_token')
      oauth_verifier = self.get_argument('oauth_verifier')
      oauth_token_secret = self.get_secure_cookie('_ponokoauth_')
      token = oauth.Token(oauth_token, oauth_token_secret)
      token.set_verifier(oauth_verifier)

      consumer = oauth.Consumer(CONSUMER_KEY, CONSUMER_SECRET)
      client = oauth.Client(consumer, token)

      resp, content = client.request(access_token_url, "POST")
      access_token = dict(urlparse.parse_qsl(content))
      #upload1(access_token)
      #upload2(access_token)
      self.redirect('/')
    except Exception, e:
      print e

def upload1(access_token):
  consumer = oauth.Consumer(CONSUMER_KEY, CONSUMER_SECRET)
  token = oauth.Token(access_token['oauth_token'],
    access_token['oauth_token_secret'])

  params = dict(name='Test', ref='2413')
  params['designs[][ref]'] = '42'
  params['designs[][file_name]'] = 'test.stl'

  faux_req = oauth.Request(method='POST', url=UPLOAD_URL, parameters=params)
  signature_method = oauth.SignatureMethod_HMAC_SHA1()
  faux_req.sign_request(signature_method, consumer, token)
  params = dict(urlparse.parse_qsl(faux_req.to_postdata()))

  files = [('designs[][uploaded_data]','test.stl',
    open('./test.stl','rb').read())]

  content_type, body = encode_multipart_formdata(params, files)
  headers = {'Content-Type': content_type, 'Content-Length': str(len(body))}
  r = urllib2.Request('%s' % UPLOAD_URL, body, headers)
  print urllib2.urlopen(r).read()

def upload2(access_token):
  consumer = oauth.Consumer(CONSUMER_KEY, CONSUMER_SECRET)
  token = oauth.Token(access_token['oauth_token'],
    access_token['oauth_token_secret'])

  upload_params = dict(name='Test', ref='2413')
  upload_params['designs[][ref]'] = '42'
  upload_params['designs[][file_name]'] = 'test.stl'

  req = oauth.Request.from_consumer_and_token(consumer, token=token, 
    http_method="POST", http_url=UPLOAD_URL, parameters=upload_params)
  req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, token)

  compiled_postdata = req.to_postdata()
  all_upload_params = urlparse.parse_qs(
    compiled_postdata, keep_blank_values=True)

  for key, val in all_upload_params.iteritems():
    all_upload_params[key] = val[0]

  all_upload_params['designs[][uploaded_data]'] = open('./test.stl','rb').read()

  datagen, headers = multipart_encode(all_upload_params)

  request = urllib2.Request(UPLOAD_URL, datagen, headers)
  
  try:
    respdata = urllib2.urlopen(request).read()
    print 'Response: ' + respdata
  except urllib2.HTTPError, ex:
    print >> sys.stderr, 'Received error code: ', ex.code
    print >> sys.stderr
    print >> sys.stderr, ex
    sys.exit(1)

def encode_multipart_formdata(fields, files):
  import mimetools
  import mimetypes
  BOUNDARY = mimetools.choose_boundary()
  CRLF = '\r\n'
  L = []
  for (key, value) in fields.items():
      L.append('--' + BOUNDARY)
      L.append('Content-Disposition: form-data; name="%s"' % key)
      L.append('')
      L.append(value)
  for (key, filename, value) in files:
      L.append('--' + BOUNDARY)
      L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
      L.append('Content-Type: %s' % mimetypes.guess_type(filename)[0] or 'application/octet-stream')
      L.append('')
      L.append(value)
  L.append('--' + BOUNDARY + '--')
  L.append('')
  body = CRLF.join(L)
  content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
  return content_type, body



if __name__ == '__main__':
  application = web.Application([
    ( '/_ponoko/request', RequestTokenFetcher ),
    ( '/_ponoko/access', AccessTokenFetcher ),
  ])
  if len(sys.argv) < 2:
    print 'Usage: python client.py <PORT>'
    sys.exit(0)
  application.listen(int(sys.argv[1]), xheaders=True)
  ioloop.IOLoop.instance().start()
