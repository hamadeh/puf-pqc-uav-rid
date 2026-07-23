%% RO-PUF process-variation analysis for a 128-RO, two-bank architecture
% This script parses LTspice .meas output, rejects incomplete simulations,
% generates 1023 unique cross-bank challenges, and compares two response
% definitions using the SAME frequency measurements:
%
%   1) Raw convention:              response = (f_A > f_B)
%   2) Balanced orientation:        approximately half use (f_A > f_B)
%                                   and half use (f_B > f_A)
%
% The balanced orientation is generated only from the challenge graph using
% an Euler-circuit edge coloring. It does NOT use the measured frequencies or
% responses, so it is not optimized on the observed devices. Every oscillator
% participates in the two comparison orientations as evenly as mathematically
% possible, and the total orientation counts are 512 versus 511.
%
% EVIDENCE BOUNDARY:
%   - This script does NOT estimate joint min-entropy from overall bias.
%   - It does NOT sum marginal entropy estimates.
%   - It does NOT calculate BCH failure probability from a hard-coded BER.
%   - Reliability, majority voting, BCH reconstruction, and decoder failure
%     belong to a separate repeated-read PVT/noise experiment.
%   - Results characterize only the adopted LTspice variation model.
%   - With N devices, centered rank cannot exceed N-1, and pairwise response
%     correlations are highly sample-limited when N is small.
%
% Requirements: MATLAB R2018b or later is recommended. No Statistics and
% Machine Learning Toolbox functions are required.

clear; clc; close all;

%% 1. USER CONFIGURATION
cfg.log_file = 'stage128ROPUF_v6.log';
cfg.output_dir = 'RO_PUF_process_results_balanced';
cfg.n_ro = 128;
cfg.bank_size = 64;
cfg.n_response_bits = 1023;
cfg.challenge_seed = 20260717;             % public, reproducible pair schedule
cfg.margin_threshold_pct = [0.01 0.05 0.10 0.20 0.50];
cfg.tie_relative_tolerance = 1e-12;
cfg.multiple_test_alpha = 0.05;
cfg.save_full_correlation = false;          % true creates a large CSV
cfg.figure_visible = 'on';                  % use 'off' for unattended execution

if cfg.n_ro ~= 2 * cfg.bank_size
    error('n_ro must equal two banks of bank_size oscillators.');
end
if cfg.n_response_bits > cfg.bank_size^2
    error('Requested challenges exceed the number of unique cross-bank pairs.');
end
if ~isfile(cfg.log_file)
    error('LTspice log file not found: %s', cfg.log_file);
end
if ~exist(cfg.output_dir, 'dir')
    mkdir(cfg.output_dir);
end

fprintf('Parsing LTspice measurements from %s ...\n', cfg.log_file);

%% 2. PARSE ALL 128 FREQUENCY MEASUREMENTS
[step_ids_all, freq_all, parse_report] = parse_ltspice_frequency_log(cfg.log_file, cfg.n_ro);

attempted_steps = numel(step_ids_all);
valid_freq = all(isfinite(freq_all) & freq_all > 0, 2);
invalid_steps = step_ids_all(~valid_freq);
invalid_missing_count = sum(~isfinite(freq_all(~valid_freq, :)), 2);
invalid_nonpositive_count = sum(isfinite(freq_all(~valid_freq, :)) & ...
    freq_all(~valid_freq, :) <= 0, 2);

if any(~valid_freq)
    failed_table = table(invalid_steps, invalid_missing_count, invalid_nonpositive_count, ...
        'VariableNames', {'step_id','missing_frequency_count','nonpositive_frequency_count'});
    writetable(failed_table, fullfile(cfg.output_dir, 'failed_steps.csv'));
end

step_ids = step_ids_all(valid_freq);
freq_matrix = freq_all(valid_freq, :);
successful_steps = numel(step_ids);

if successful_steps < 2
    error('Only %d complete devices were found. At least two are required.', successful_steps);
end

fprintf('Attempted steps: %d; complete steps: %d; rejected steps: %d.\n', ...
    attempted_steps, successful_steps, attempted_steps-successful_steps);

%% 3. GENERATE FIXED PAIRS AND A DATA-INDEPENDENT BALANCED ORIENTATION
% The pair schedule uses 16 cyclic offsets, creating 1024 distinct pairs,
% then removes one pair. Every RO appears 15 or 16 times.
challenge = generate_balanced_schedule(cfg.bank_size, cfg.n_response_bits, ...
    cfg.challenge_seed);
assert(size(unique(challenge, 'rows'), 1) == cfg.n_response_bits, ...
    'Challenge schedule contains duplicate pairs.');

usage_A = accumarray(challenge(:,1), 1, [cfg.bank_size 1]);
usage_B = accumarray(challenge(:,2), 1, [cfg.bank_size 1]);
if (max(usage_A)-min(usage_A) > 1) || (max(usage_B)-min(usage_B) > 1)
    error('Challenge schedule is not balanced across the two banks.');
end

% orientation = +1 means compare f_A > f_B.
% orientation = -1 means compare f_B > f_A.
% The Euler construction balances the two orientations at every RO without
% inspecting any frequency or response value.
orientation = generate_euler_balanced_orientation(challenge, cfg.bank_size);
orientation_plus_count = sum(orientation == 1);
orientation_minus_count = sum(orientation == -1);

plus_usage_A = accumarray(challenge(:,1), orientation == 1, [cfg.bank_size 1]);
plus_usage_B = accumarray(challenge(:,2), orientation == 1, [cfg.bank_size 1]);
minus_usage_A = usage_A - plus_usage_A;
minus_usage_B = usage_B - plus_usage_B;
orientation_imbalance_A = abs(plus_usage_A-minus_usage_A);
orientation_imbalance_B = abs(plus_usage_B-minus_usage_B);

if abs(orientation_plus_count-orientation_minus_count) ~= 1
    error('The 1023-bit orientation schedule must contain 512 versus 511 comparisons.');
end
if max([orientation_imbalance_A; orientation_imbalance_B]) > 1
    error('Orientation use is not balanced at each oscillator.');
end

first_global_ro = challenge(:,1)-1;
second_global_ro = cfg.bank_size + challenge(:,2)-1;
reverse_mask = orientation == -1;
first_global_ro(reverse_mask) = cfg.bank_size + challenge(reverse_mask,2)-1;
second_global_ro(reverse_mask) = challenge(reverse_mask,1)-1;

challenge_table = table((0:cfg.n_response_bits-1)', challenge(:,1)-1, ...
    challenge(:,2)-1, challenge(:,1)-1, ...
    cfg.bank_size + challenge(:,2)-1, orientation, ...
    first_global_ro, second_global_ro, ...
    'VariableNames', {'challenge_index','bank_A_index','bank_B_index', ...
    'global_RO_A_index','global_RO_B_index','orientation_code', ...
    'first_global_RO_index','second_global_RO_index'});
writetable(challenge_table, fullfile(cfg.output_dir, 'challenge_schedule.csv'));
save(fullfile(cfg.output_dir, 'RO_PUF_challenge_schedule.mat'), ...
    'challenge','orientation','usage_A','usage_B','plus_usage_A','plus_usage_B');

%% 4. CONSTRUCT RAW AND BALANCED-ORIENTATION RESPONSES
idx_A = challenge(:,1);
idx_B = cfg.bank_size + challenge(:,2);
freq_A_all = freq_matrix(:, idx_A);
freq_B_all = freq_matrix(:, idx_B);
mean_pair_freq_all = (freq_A_all + freq_B_all) / 2;
relative_margin_all = abs(freq_A_all-freq_B_all) ./ mean_pair_freq_all;

tie_mask = relative_margin_all <= cfg.tie_relative_tolerance;
chips_with_ties = any(tie_mask, 2);
if any(chips_with_ties)
    tie_steps = step_ids(chips_with_ties);
    tie_counts = sum(tie_mask(chips_with_ties,:), 2);
    writetable(table(tie_steps, tie_counts), ...
        fullfile(cfg.output_dir, 'tie_steps.csv'));
    warning('%d complete-frequency devices contain exact/indistinguishable ties and will be excluded.', ...
        sum(chips_with_ties));
end

analysis_mask = ~chips_with_ties;
analysis_step_ids = step_ids(analysis_mask);
analysis_freq = freq_matrix(analysis_mask, :);
freq_A = freq_A_all(analysis_mask, :);
freq_B = freq_B_all(analysis_mask, :);
relative_margin = relative_margin_all(analysis_mask, :);

raw_response = freq_A > freq_B;
response = raw_response;
response(:, orientation == -1) = ~response(:, orientation == -1);
N = size(response, 1);

if N < 2
    error('Fewer than two tie-free devices remain after validation.');
end

%% 5. BANK-OFFSET DIAGNOSTIC AND ORIENTATION COMPARISON
bank_A_mean_per_chip = mean(analysis_freq(:,1:cfg.bank_size), 2);
bank_B_mean_per_chip = mean(analysis_freq(:,cfg.bank_size+1:end), 2);
bank_offset_fraction = (bank_A_mean_per_chip-bank_B_mean_per_chip) ./ ...
    ((bank_A_mean_per_chip+bank_B_mean_per_chip)/2);
bank_offset_pct = bank_offset_fraction * 100;

raw_chip_uniformity = mean(raw_response, 2) * 100;
chip_uniformity = mean(response, 2) * 100;

[raw_pearson_r, raw_pearson_p] = pearson_corr_p(bank_offset_pct, raw_chip_uniformity);
[balanced_pearson_r, balanced_pearson_p] = pearson_corr_p(bank_offset_pct, chip_uniformity);
[raw_spearman_r, raw_spearman_p] = spearman_corr_p(bank_offset_pct, raw_chip_uniformity);
[balanced_spearman_r, balanced_spearman_p] = spearman_corr_p(bank_offset_pct, chip_uniformity);

raw_uniformity_mean = mean(raw_chip_uniformity);
raw_uniformity_std = std(raw_chip_uniformity, 0);
balanced_uniformity_mean = mean(chip_uniformity);
balanced_uniformity_std = std(chip_uniformity, 0);
uniformity_std_reduction_pct = ...
    (raw_uniformity_std-balanced_uniformity_std) / max(raw_uniformity_std, eps) * 100;

%% 6. CORE PUF POPULATION METRICS FOR THE BALANCED RESPONSE
raw_overall_uniformity = mean(raw_response(:)) * 100;
overall_uniformity = mean(response(:)) * 100;

raw_hd_all = pairwise_hamming_percent(raw_response);
hd_all = pairwise_hamming_percent(response);

uniqueness_mean = mean(hd_all);
uniqueness_std = std(hd_all, 0);
uniqueness_median = median(hd_all);
uniqueness_p05 = percentile_no_toolbox(hd_all, 5);
uniqueness_p95 = percentile_no_toolbox(hd_all, 95);
uniqueness_min = min(hd_all);
uniqueness_max = max(hd_all);

raw_uniqueness_mean = mean(raw_hd_all);
raw_uniqueness_std = std(raw_hd_all, 0);

ones_count = sum(response, 1);
bit_alias = ones_count / N;
[alias_ci_low, alias_ci_high] = wilson_interval(ones_count, N, 1.96);

% Per-position marginal lower confidence bounds. Do not sum these values.
pmax_upper = max(alias_ci_high, 1-alias_ci_low);
marginal_hmin_lb = -log2(min(pmax_upper, 1));

uncorrected_ci_flag = alias_ci_high < 0.5 | alias_ci_low > 0.5;
bits_ci_excludes_half = sum(uncorrected_ci_flag);
constant_bits = sum(bit_alias == 0 | bit_alias == 1);

% Exact equal-tail two-sided binomial tests against p=0.5, followed by
% Benjamini-Hochberg FDR and Bonferroni corrections across all 1023 bits.
binomial_p = binomial_two_sided_p(ones_count, N, 0.5);
[bh_q, bh_reject] = benjamini_hochberg(binomial_p, cfg.multiple_test_alpha);
bonferroni_adjusted_p = min(1, binomial_p * cfg.n_response_bits);
bonferroni_reject = bonferroni_adjusted_p <= cfg.multiple_test_alpha;

%% 7. FREQUENCY AND MARGIN DIAGNOSTICS
frequency_mean_hz = mean(analysis_freq(:));
frequency_std_hz = std(analysis_freq(:), 0);
frequency_min_hz = min(analysis_freq(:));
frequency_max_hz = max(analysis_freq(:));

margin_pct = relative_margin * 100;
margin_fraction = zeros(numel(cfg.margin_threshold_pct),1);
for k = 1:numel(cfg.margin_threshold_pct)
    margin_fraction(k) = mean(margin_pct(:) < cfg.margin_threshold_pct(k)) * 100;
end

margin_per_bit_median = median(margin_pct, 1);
margin_per_bit_p05 = column_percentile(margin_pct, 5);

%% 8. DEPENDENCE DIAGNOSTICS -- NOT AN ENTROPY ESTIMATE
response_double = double(response);
bit_variance = var(response_double, 0, 1);
variable_bit_mask = bit_variance > 0;
variable_bit_count = sum(variable_bit_mask);

if variable_bit_count >= 2
    C = corrcoef(response_double(:,variable_bit_mask));
    C(1:size(C,1)+1:end) = NaN;
    abs_corr = abs(C(~isnan(C)));
    mean_abs_corr = mean(abs_corr);
    median_abs_corr = median(abs_corr);
    p95_abs_corr = percentile_no_toolbox(abs_corr, 95);
    max_abs_corr = max(abs_corr);
else
    C = NaN;
    mean_abs_corr = NaN;
    median_abs_corr = NaN;
    p95_abs_corr = NaN;
    max_abs_corr = NaN;
end

X = response_double - mean(response_double,1);
singular_values = svd(X, 'econ');
eigenvalues = singular_values.^2 / max(N-1,1);
if sum(eigenvalues.^2) > 0
    effective_rank_participation = (sum(eigenvalues)^2) / sum(eigenvalues.^2);
else
    effective_rank_participation = 0;
end
linear_rank = rank(X);
maximum_observable_centered_rank = min(N-1, cfg.n_response_bits);

% Expected magnitude of sample correlation for independent variables under
% a rough normal approximation. This is contextual only, not a correction.
small_sample_abs_corr_reference = sqrt(2/(pi*max(N-1,1)));

% Absolute architecture-level ceiling: all response bits are deterministic
% functions of the ordering of 128 scalar oscillator frequencies.
architecture_entropy_ceiling_bits = gammaln(cfg.n_ro + 1) / log(2);

%% 9. SAVE DATA PRODUCTS
freq_names = arrayfun(@(k) sprintf('freq_ro%d_hz', k), ...
    0:cfg.n_ro-1, 'UniformOutput', false);
freq_table = array2table(analysis_freq, 'VariableNames', freq_names);
freq_table = addvars(freq_table, analysis_step_ids, 'Before', 1, ...
    'NewVariableNames', 'step_id');
writetable(freq_table, fullfile(cfg.output_dir, 'frequency_matrix_valid.csv'));

response_names = arrayfun(@(k) sprintf('r%d', k), ...
    0:cfg.n_response_bits-1, 'UniformOutput', false);
response_table = array2table(uint8(response), 'VariableNames', response_names);
response_table = addvars(response_table, analysis_step_ids, 'Before', 1, ...
    'NewVariableNames', 'step_id');
writetable(response_table, fullfile(cfg.output_dir, 'response_matrix_balanced.csv'));

raw_response_table = array2table(uint8(raw_response), 'VariableNames', response_names);
raw_response_table = addvars(raw_response_table, analysis_step_ids, 'Before', 1, ...
    'NewVariableNames', 'step_id');
writetable(raw_response_table, fullfile(cfg.output_dir, 'response_matrix_raw_A_gt_B.csv'));

alias_table = table((0:cfg.n_response_bits-1)', bit_alias(:)*100, ...
    alias_ci_low(:)*100, alias_ci_high(:)*100, marginal_hmin_lb(:), ...
    binomial_p(:), bh_q(:), bh_reject(:), ...
    bonferroni_adjusted_p(:), bonferroni_reject(:), ...
    uncorrected_ci_flag(:), margin_per_bit_median(:), margin_per_bit_p05(:), ...
    'VariableNames', {'bit_index','bit_alias_percent','ci95_low_percent', ...
    'ci95_high_percent','marginal_hmin_lower_bound_bits', ...
    'binomial_two_sided_p','BH_FDR_q','BH_FDR_reject', ...
    'bonferroni_adjusted_p','bonferroni_reject', ...
    'uncorrected_CI_excludes_50','median_margin_percent','p05_margin_percent'});
writetable(alias_table, fullfile(cfg.output_dir, 'bit_statistics.csv'));

chip_table = table(analysis_step_ids, raw_chip_uniformity, chip_uniformity, ...
    bank_offset_pct, ...
    'VariableNames', {'step_id','raw_uniformity_percent', ...
    'balanced_uniformity_percent','bank_A_minus_B_mean_percent'});
writetable(chip_table, fullfile(cfg.output_dir, 'chip_statistics.csv'));

orientation_table = table((0:cfg.bank_size-1)', usage_A, plus_usage_A, ...
    minus_usage_A, orientation_imbalance_A, usage_B, plus_usage_B, ...
    minus_usage_B, orientation_imbalance_B, ...
    'VariableNames', {'local_RO_index','bank_A_total_usage', ...
    'bank_A_A_gt_B_usage','bank_A_B_gt_A_usage','bank_A_orientation_imbalance', ...
    'bank_B_total_usage','bank_B_A_gt_B_usage','bank_B_B_gt_A_usage', ...
    'bank_B_orientation_imbalance'});
writetable(orientation_table, fullfile(cfg.output_dir, 'orientation_balance.csv'));

margin_table = table(cfg.margin_threshold_pct(:), margin_fraction, ...
    'VariableNames', {'margin_threshold_percent','fraction_below_threshold_percent'});
writetable(margin_table, fullfile(cfg.output_dir, 'margin_summary.csv'));

if cfg.save_full_correlation && variable_bit_count >= 2
    writematrix(C, fullfile(cfg.output_dir, ...
        'variable_bit_correlation_matrix.csv'));
end

save(fullfile(cfg.output_dir, 'RO_PUF_process_results.mat'), ...
    'cfg','parse_report','step_ids_all','freq_all','valid_freq', ...
    'analysis_step_ids','analysis_freq','challenge','orientation', ...
    'raw_response','response','relative_margin','raw_chip_uniformity', ...
    'chip_uniformity','raw_hd_all','hd_all','bit_alias','alias_ci_low', ...
    'alias_ci_high','marginal_hmin_lb','binomial_p','bh_q','bh_reject', ...
    'bonferroni_adjusted_p','bonferroni_reject','bank_offset_pct', ...
    'C','singular_values','eigenvalues','effective_rank_participation', ...
    'linear_rank');

%% 10. GENERATE FIGURES
fig1 = figure('Visible', cfg.figure_visible);
histogram(hd_all, 'Normalization', 'probability', 'BinWidth', 1);
xlabel('Inter-instance Hamming distance (%)'); ylabel('Probability');
title(sprintf('Balanced response HD: mean %.2f%%, N=%d', uniqueness_mean, N));
grid on; xline(50, '--', 'Reference: 50%');
save_figure(fig1, fullfile(cfg.output_dir, 'inter_instance_hd_balanced.png'));

fig2 = figure('Visible', cfg.figure_visible);
histogram(chip_uniformity, 'Normalization', 'probability', 'BinWidth', 1);
xlabel('Balanced response uniformity per device (%)'); ylabel('Probability');
title(sprintf('Balanced uniformity: mean %.2f%%, std %.2f%%', ...
    mean(chip_uniformity), std(chip_uniformity,0)));
grid on; xline(50, '--', 'Reference: 50%');
save_figure(fig2, fullfile(cfg.output_dir, 'chip_uniformity_balanced.png'));

fig3 = figure('Visible', cfg.figure_visible);
errorbar(0:cfg.n_response_bits-1, bit_alias*100, ...
    (bit_alias-alias_ci_low)*100, (alias_ci_high-bit_alias)*100, ...
    '.', 'MarkerSize', 4);
xlabel('Response position'); ylabel('Bit alias (%)');
title('Balanced response bit alias with 95% Wilson intervals');
grid on; yline(50, '--', 'Reference: 50%');
save_figure(fig3, fullfile(cfg.output_dir, 'bit_alias_wilson_balanced.png'));

fig4 = figure('Visible', cfg.figure_visible);
bar(cfg.margin_threshold_pct, margin_fraction);
xlabel('Relative frequency-margin threshold (%)');
ylabel('Comparisons below threshold (%)');
title('Small-margin comparison frequency'); grid on;
save_figure(fig4, fullfile(cfg.output_dir, 'small_margin_statistics.png'));

fig5 = figure('Visible', cfg.figure_visible);
scatter(bank_offset_pct, raw_chip_uniformity, 60, 'filled');
xlabel('Mean Bank-A minus Bank-B frequency offset (%)');
ylabel('Raw all-A>B uniformity (%)');
title(sprintf('Raw bank-offset diagnostic: Pearson r=%.3f, p=%.3g', ...
    raw_pearson_r, raw_pearson_p));
grid on; yline(50, '--', 'Reference: 50%');
save_figure(fig5, fullfile(cfg.output_dir, 'bank_offset_vs_raw_uniformity.png'));

fig6 = figure('Visible', cfg.figure_visible);
scatter(bank_offset_pct, chip_uniformity, 60, 'filled');
xlabel('Mean Bank-A minus Bank-B frequency offset (%)');
ylabel('Balanced-orientation uniformity (%)');
title(sprintf('Balanced bank-offset diagnostic: Pearson r=%.3f, p=%.3g', ...
    balanced_pearson_r, balanced_pearson_p));
grid on; yline(50, '--', 'Reference: 50%');
save_figure(fig6, fullfile(cfg.output_dir, ...
    'bank_offset_vs_balanced_uniformity.png'));

fig7 = figure('Visible', cfg.figure_visible);
plot(raw_chip_uniformity, chip_uniformity, 'o', 'MarkerSize', 7);
xlabel('Raw all-A>B uniformity (%)');
ylabel('Balanced-orientation uniformity (%)');
title('Per-device uniformity before and after orientation balancing');
grid on; xline(50, '--'); yline(50, '--');
save_figure(fig7, fullfile(cfg.output_dir, 'raw_vs_balanced_uniformity.png'));

%% 11. SUMMARY
simulation_yield = successful_steps / attempted_steps * 100;
tie_free_yield = N / attempted_steps * 100;

fprintf('\n================ PROCESS-VARIATION SUMMARY ================\n');
fprintf('Attempted LTspice devices                  : %d\n', attempted_steps);
fprintf('Complete-frequency devices                : %d\n', successful_steps);
fprintf('Tie-free devices used                     : %d\n', N);
fprintf('Complete-frequency simulation yield       : %.2f %%\n', simulation_yield);
fprintf('Final tie-free analysis yield              : %.2f %%\n', tie_free_yield);
fprintf('Physical ring oscillators                 : %d (two banks of %d)\n', ...
    cfg.n_ro, cfg.bank_size);
fprintf('Unique cross-bank challenge positions     : %d\n', cfg.n_response_bits);
fprintf('Challenge usage per RO, bank A            : %d to %d\n', ...
    min(usage_A), max(usage_A));
fprintf('Challenge usage per RO, bank B            : %d to %d\n', ...
    min(usage_B), max(usage_B));
fprintf('Orientation count A>B / B>A               : %d / %d\n', ...
    orientation_plus_count, orientation_minus_count);
fprintf('Maximum per-RO orientation imbalance      : %d comparison\n', ...
    max([orientation_imbalance_A; orientation_imbalance_B]));

fprintf('\n--- Bank-offset diagnostic ---\n');
fprintf('Bank-offset range                         : %.4f to %.4f %%\n', ...
    min(bank_offset_pct), max(bank_offset_pct));
fprintf('Raw Pearson r / p                         : %.4f / %.4g\n', ...
    raw_pearson_r, raw_pearson_p);
fprintf('Balanced Pearson r / p                    : %.4f / %.4g\n', ...
    balanced_pearson_r, balanced_pearson_p);
fprintf('Raw Spearman rho / p                      : %.4f / %.4g\n', ...
    raw_spearman_r, raw_spearman_p);
fprintf('Balanced Spearman rho / p                 : %.4f / %.4g\n', ...
    balanced_spearman_r, balanced_spearman_p);

fprintf('\n--- Raw versus balanced response ---\n');
fprintf('Raw overall uniformity                    : %.3f %%\n', ...
    raw_overall_uniformity);
fprintf('Balanced overall uniformity               : %.3f %%\n', ...
    overall_uniformity);
fprintf('Raw per-device uniformity mean / std      : %.3f / %.3f %%\n', ...
    raw_uniformity_mean, raw_uniformity_std);
fprintf('Balanced per-device uniformity mean / std : %.3f / %.3f %%\n', ...
    balanced_uniformity_mean, balanced_uniformity_std);
fprintf('Uniformity-std change                     : %.2f %% reduction\n', ...
    uniformity_std_reduction_pct);
fprintf('Raw inter-instance HD mean / std          : %.3f / %.3f %%\n', ...
    raw_uniqueness_mean, raw_uniqueness_std);
fprintf('Balanced inter-instance HD mean / std     : %.3f / %.3f %%\n', ...
    uniqueness_mean, uniqueness_std);
fprintf('Balanced HD median [5th,95th]             : %.3f [%.3f, %.3f] %%\n', ...
    uniqueness_median, uniqueness_p05, uniqueness_p95);
fprintf('Balanced HD range                         : %.3f to %.3f %%\n', ...
    uniqueness_min, uniqueness_max);

fprintf('\n--- Frequency, alias, and dependence ---\n');
fprintf('Mean oscillator frequency                 : %.6e Hz\n', frequency_mean_hz);
fprintf('Oscillator-frequency std / range          : %.6e / [%.6e, %.6e] Hz\n', ...
    frequency_std_hz, frequency_min_hz, frequency_max_hz);
fprintf('Mean balanced bit alias                   : %.3f %%\n', mean(bit_alias)*100);
fprintf('Balanced bit-alias range                  : %.3f to %.3f %%\n', ...
    min(bit_alias)*100, max(bit_alias)*100);
fprintf('Constant response positions               : %d of %d\n', ...
    constant_bits, cfg.n_response_bits);
fprintf('Uncorrected Wilson CIs excluding 50%%      : %d of %d\n', ...
    bits_ci_excludes_half, cfg.n_response_bits);
fprintf('BH-FDR significant positions (q<=%.2f)    : %d of %d\n', ...
    cfg.multiple_test_alpha, sum(bh_reject), cfg.n_response_bits);
fprintf('Bonferroni significant positions          : %d of %d\n', ...
    sum(bonferroni_reject), cfg.n_response_bits);
fprintf('Marginal Hmin lower-bound range           : %.4f to %.4f bits/position\n', ...
    min(marginal_hmin_lb), max(marginal_hmin_lb));
fprintf('Variable response positions               : %d\n', variable_bit_count);
fprintf('Mean / 95th / max absolute correlation    : %.4f / %.4f / %.4f\n', ...
    mean_abs_corr, p95_abs_corr, max_abs_corr);
fprintf('Small-sample |correlation| reference       : %.4f\n', ...
    small_sample_abs_corr_reference);
fprintf('Centered response linear rank             : %d (maximum observable %d)\n', ...
    linear_rank, maximum_observable_centered_rank);
fprintf('Participation-ratio effective rank        : %.2f (sample-limited)\n', ...
    effective_rank_participation);
fprintf('Architecture entropy ceiling log2(128!)   : %.2f bits\n', ...
    architecture_entropy_ceiling_bits);

fprintf('\nNo joint min-entropy or BCH failure claim is produced by this script.\n');
fprintf('The balanced orientation is fixed and independent of the measured data.\n');
fprintf('Use repeated PVT/noise reads and an actual decoder for reliability/BCH results.\n');
fprintf('Output directory: %s\n', cfg.output_dir);
fprintf('===========================================================\n');

%% LOCAL FUNCTIONS
function [step_ids, freq_matrix, report] = parse_ltspice_frequency_log(log_file, n_ro)
    fid = fopen(log_file, 'r');
    if fid < 0
        error('Cannot open log file: %s', log_file);
    end
    cleanup = onCleanup(@() fclose(fid)); %#ok<NASGU>
    raw = textscan(fid, '%s', 'Delimiter', '\n', 'Whitespace', '');
    lines = raw{1};

    measurements = cell(n_ro,1);
    all_steps = [];
    duplicate_entries = 0;

    i = 1;
    while i <= numel(lines)
        header = regexp(strtrim(lines{i}), ...
            '^Measurement:\s*freq_ro(\d+)\s*$', 'tokens', 'once');
        if isempty(header)
            i = i + 1;
            continue;
        end

        ro = str2double(header{1});
        i = i + 1;
        step_vec = [];
        value_vec = [];

        while i <= numel(lines) && ...
                isempty(regexp(strtrim(lines{i}), '^Measurement:', 'once'))
            tok = regexp(strtrim(lines{i}), '^(\d+)\s+(\S+)', 'tokens', 'once');
            if ~isempty(tok)
                step_vec(end+1,1) = str2double(tok{1}); %#ok<AGROW>
                parsed_value = str2double(tok{2});
                if isnan(parsed_value)
                    parsed_value = NaN;
                end
                value_vec(end+1,1) = parsed_value; %#ok<AGROW>
            end
            i = i + 1;
        end

        if ro >= 0 && ro < n_ro
            if ~isempty(measurements{ro+1})
                duplicate_entries = duplicate_entries + 1;
            end
            measurements{ro+1} = [step_vec value_vec];
            all_steps = [all_steps; step_vec]; %#ok<AGROW>
        end
    end

    if isempty(all_steps)
        error('No freq_ro0...freq_ro%d measurement rows were found.', n_ro-1);
    end

    step_ids = unique(all_steps, 'sorted');
    freq_matrix = NaN(numel(step_ids), n_ro);
    missing_measurements = [];

    for ro = 1:n_ro
        data = measurements{ro};
        if isempty(data)
            missing_measurements(end+1) = ro-1; %#ok<AGROW>
            continue;
        end
        [present, row_idx] = ismember(data(:,1), step_ids);
        rows = row_idx(present);
        values = data(present,2);
        if numel(unique(rows)) ~= numel(rows)
            error('Duplicate step rows detected in freq_ro%d.', ro-1);
        end
        freq_matrix(rows,ro) = values;
    end

    report = struct();
    report.missing_measurement_indices = missing_measurements;
    report.duplicate_measurement_blocks = duplicate_entries;
    report.detected_step_count = numel(step_ids);

    if ~isempty(missing_measurements)
        warning('Missing entire measurement blocks for RO indices: %s', ...
            mat2str(missing_measurements));
    end
end

function schedule = generate_balanced_schedule(bank_size, n_bits, seed)
    if n_bits > bank_size^2
        error('n_bits exceeds the available unique cross-bank pairs.');
    end

    old_rng = rng;
    cleanup = onCleanup(@() rng(old_rng)); %#ok<NASGU>
    rng(seed, 'twister');

    n_offsets = ceil(n_bits / bank_size);
    if n_offsets > bank_size
        error('Requested schedule requires more offsets than available.');
    end

    perm_A = randperm(bank_size);
    perm_B = randperm(bank_size);
    offsets = randperm(bank_size, n_offsets) - 1;

    full_schedule = zeros(n_offsets*bank_size, 2);
    row = 0;
    for s = 1:n_offsets
        for pos = 0:bank_size-1
            row = row + 1;
            full_schedule(row,1) = perm_A(pos+1);
            b_pos = mod(pos + offsets(s), bank_size) + 1;
            full_schedule(row,2) = perm_B(b_pos);
        end
    end

    order = randperm(size(full_schedule,1));
    full_schedule = full_schedule(order,:);
    schedule = full_schedule(1:n_bits,:);
end

function orientation = generate_euler_balanced_orientation(challenge, bank_size)
% Edge-color the bipartite challenge graph alternately along an Euler circuit.
% For the 1023-edge, degree-15/16 graph there are exactly two odd-degree
% vertices. Adding one dummy edge makes every degree even and produces a
% 1024-edge Euler circuit. Alternating colors along that circuit, then removing
% the dummy edge, leaves 512 versus 511 colors and per-vertex imbalance <= 1.

    n_vertices = 2*bank_size;
    edges = [challenge(:,1), bank_size+challenge(:,2)];
    degree = accumarray(edges(:), 1, [n_vertices 1]);
    odd_vertices = find(mod(degree,2) == 1);

    if numel(odd_vertices) ~= 2
        error(['Expected exactly two odd-degree vertices for this 1023-edge ' ...
            'balanced schedule; found %d.'], numel(odd_vertices));
    end

    original_edge_count = size(edges,1);
    edges(end+1,:) = odd_vertices(:)';
    dummy_edge = size(edges,1);

    adjacency = cell(n_vertices,1);
    for e = 1:size(edges,1)
        u = edges(e,1);
        v = edges(e,2);
        adjacency{u}(end+1) = e; %#ok<AGROW>
        adjacency{v}(end+1) = e; %#ok<AGROW>
    end

    used = false(size(edges,1),1);
    next_position = ones(n_vertices,1);
    vertex_stack = edges(1,1);
    edge_stack = zeros(0,1);
    reverse_circuit_edges = zeros(size(edges,1),1);
    circuit_count = 0;

    while ~isempty(vertex_stack)
        v = vertex_stack(end);
        while next_position(v) <= numel(adjacency{v}) && ...
                used(adjacency{v}(next_position(v)))
            next_position(v) = next_position(v) + 1;
        end

        if next_position(v) <= numel(adjacency{v})
            e = adjacency{v}(next_position(v));
            next_position(v) = next_position(v) + 1;
            if used(e)
                continue;
            end
            used(e) = true;
            if edges(e,1) == v
                next_v = edges(e,2);
            else
                next_v = edges(e,1);
            end
            vertex_stack(end+1) = next_v; %#ok<AGROW>
            edge_stack(end+1) = e; %#ok<AGROW>
        else
            vertex_stack(end) = [];
            if ~isempty(edge_stack)
                circuit_count = circuit_count + 1;
                reverse_circuit_edges(circuit_count) = edge_stack(end);
                edge_stack(end) = [];
            end
        end
    end

    if ~all(used)
        error('Challenge graph is disconnected; Euler orientation was not completed.');
    end

    circuit_edges = flipud(reverse_circuit_edges(1:circuit_count));
    if numel(circuit_edges) ~= size(edges,1)
        error('Euler circuit does not contain every edge exactly once.');
    end

    edge_color = zeros(size(edges,1),1);
    edge_color(circuit_edges(1:2:end)) = 1;
    edge_color(circuit_edges(2:2:end)) = -1;

    orientation = edge_color(1:original_edge_count);
    if edge_color(dummy_edge) == 0
        error('Dummy edge was not included in the Euler circuit.');
    end
end

function hd = pairwise_hamming_percent(response)
    N = size(response,1);
    L = size(response,2);
    hd = zeros(N*(N-1)/2,1);
    cursor = 0;
    for i = 1:N-1
        block = sum(response(i+1:end,:) ~= response(i,:), 2) / L * 100;
        hd(cursor+1:cursor+numel(block)) = block;
        cursor = cursor + numel(block);
    end
end

function [low, high] = wilson_interval(successes, n, z)
    p = successes / n;
    denom = 1 + z^2/n;
    center = (p + z^2/(2*n)) / denom;
    half = z * sqrt((p.*(1-p) + z^2/(4*n))/n) / denom;
    low = max(0, center-half);
    high = min(1, center+half);
end

function p_values = binomial_two_sided_p(successes, n, p0)
% Exact equal-tail two-sided binomial p-values, implemented without toolbox.
    k_values = 0:n;
    log_pmf = gammaln(n+1)-gammaln(k_values+1)-gammaln(n-k_values+1) + ...
        k_values*log(p0) + (n-k_values)*log(1-p0);
    pmf = exp(log_pmf);
    pmf = pmf / sum(pmf);
    cdf_lower = cumsum(pmf);
    cdf_upper = fliplr(cumsum(fliplr(pmf)));

    p_values = zeros(size(successes));
    for i = 1:numel(successes)
        k = successes(i);
        p_values(i) = min(1, 2*min(cdf_lower(k+1), cdf_upper(k+1)));
    end
end

function [q_values, reject] = benjamini_hochberg(p_values, alpha)
    original_size = size(p_values);
    p = p_values(:);
    m = numel(p);
    [p_sorted, order] = sort(p);

    q_sorted = p_sorted .* m ./ (1:m)';
    for i = m-1:-1:1
        q_sorted(i) = min(q_sorted(i), q_sorted(i+1));
    end
    q_sorted = min(q_sorted, 1);

    q = zeros(m,1);
    q(order) = q_sorted;
    q_values = reshape(q, original_size);
    reject = q_values <= alpha;
end

function [r, p] = pearson_corr_p(x, y)
    x = x(:); y = y(:);
    valid = isfinite(x) & isfinite(y);
    x = x(valid); y = y(valid);
    n = numel(x);

    if n < 3 || std(x) == 0 || std(y) == 0
        r = NaN; p = NaN;
        return;
    end

    R = corrcoef(x,y);
    r = R(1,2);
    r = max(-1, min(1, r));

    if abs(r) >= 1
        p = 0;
        return;
    end

    df = n-2;
    t2 = (r^2 * df) / max(1-r^2, realmin);
    p = betainc(df/(df+t2), df/2, 0.5);
end

function [rho, p] = spearman_corr_p(x, y)
    rx = average_ranks(x(:));
    ry = average_ranks(y(:));
    [rho, p] = pearson_corr_p(rx, ry);
end

function ranks = average_ranks(x)
    ranks = NaN(size(x));
    valid_idx = find(isfinite(x));
    values = x(valid_idx);
    [sorted_values, order] = sort(values);
    sorted_ranks = zeros(size(values));

    i = 1;
    while i <= numel(values)
        j = i;
        while j < numel(values) && sorted_values(j+1) == sorted_values(i)
            j = j + 1;
        end
        sorted_ranks(i:j) = (i+j)/2;
        i = j + 1;
    end

    temporary = zeros(size(values));
    temporary(order) = sorted_ranks;
    ranks(valid_idx) = temporary;
end

function q = percentile_no_toolbox(x, pct)
    x = sort(x(:));
    if isempty(x)
        q = NaN;
        return;
    end
    position = 1 + (numel(x)-1) * pct/100;
    lo = floor(position);
    hi = ceil(position);
    if lo == hi
        q = x(lo);
    else
        q = x(lo) + (position-lo) * (x(hi)-x(lo));
    end
end

function q = column_percentile(X, pct)
    Xs = sort(X,1);
    n = size(Xs,1);
    position = 1 + (n-1) * pct/100;
    lo = floor(position);
    hi = ceil(position);
    if lo == hi
        q = Xs(lo,:);
    else
        q = Xs(lo,:) + (position-lo) * (Xs(hi,:)-Xs(lo,:));
    end
end

function save_figure(fig, filename)
    try
        exportgraphics(fig, filename, 'Resolution', 300);
    catch
        saveas(fig, filename);
    end
end
