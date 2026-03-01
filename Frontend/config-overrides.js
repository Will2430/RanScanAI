module.exports = function override(config) {
  // Disable symlink resolution so webpack treats the src/pages junction
  // as if the files physically reside inside src/, allowing CRA's Babel
  // transforms and ModuleScopePlugin to work correctly.
  config.resolve.symlinks = false;
  return config;
};
