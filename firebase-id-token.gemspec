# encoding: utf-8
# Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Gem::Specification.new do |s|
  s.name = 'firebase-id-token'
  s.version = '0.0.1'

  s.homepage = 'https://github.com/darnreich/firebase-id-token'
  s.license = 'APACHE-2.0'
  s.summary = 'Firebase ID Token utilities'
  s.description = 'Firebase ID Token utilities; currently just a parser/checker'

  s.files = ['lib/firebase-id-token.rb' ]

  s.add_runtime_dependency 'multi_json'
  s.add_runtime_dependency 'jwt', '>= 1'

  s.add_development_dependency 'fakeweb'
  s.add_development_dependency 'rake'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'openssl'

  s.authors = ['Daniel Arnreich']
  s.email = 'daniel@arnreich.de'
end
