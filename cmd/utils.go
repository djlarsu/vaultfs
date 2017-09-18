// Copyright © 2016 Asteris, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"flag"
	"github.com/spf13/viper"
	"github.com/wrouesnel/go.log"
	"golang.org/x/sys/unix"
)

func initLogging() {
	if err := flag.Set("log.level", viper.GetString("log-level")); err != nil {
		log.Errorln("Invalid log-level:", err)
	}
	if err := flag.Set("log.format", viper.GetString("log-level")); err != nil {
		log.Errorln("Invalid log-format:", err)
	}
}

func lockMemory() {
	err := unix.Mlockall(unix.MCL_FUTURE | unix.MCL_CURRENT)
	switch err {
	case nil:
	case unix.ENOSYS:
		log.With("error", err).Warn("mlockall() not implemented on this system")
	case unix.ENOMEM:
		log.With("error", err).Warn("mlockall() failed with ENOMEM")
	default:
		log.With("error", err).Warn("could not perform mlockall to prevent swapping memory")
	}
}
