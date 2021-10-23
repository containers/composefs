/*
  Copyright 2017 Giuseppe Scrivano <giuseppe@scrivano.org>

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#ifndef READ_FILE_H
#define READ_FILE_H

#include <stddef.h>
#include <stdio.h>

extern char *fread_file(FILE *stream, size_t *length);

extern char *read_file(const char *path, size_t *length);

#endif
