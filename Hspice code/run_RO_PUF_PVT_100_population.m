function run_RO_PUF_PVT_100_population()
%RUN_RO_PUF_PVT_100_POPULATION
%
% Population-level fixed-mismatch RO-PUF PVT analysis for 100 simulated
% devices. Each device is evaluated at nine voltage-temperature conditions.
%
% REQUIRED FILES:
%   challenge_schedule.csv
%
%   RO_PUF_PVT_100/chip_001_PVT.log
%   ...
%   RO_PUF_PVT_100/chip_100_PVT.log
%
% REQUIRED MATLAB PRODUCT:
%   Communications Toolbox:
%       gf, bchnumerr, bchenc, bchdec
%
% FINAL FROZEN DESIGN:
%   Candidate comparisons : 1023
%   Enrollment condition  : 1.0 V, 25 degC
%   Margin threshold      : 0.5%
%   Selected positions    : top 950
%   Parent BCH            : (1023,943), t=8
%   Shortened BCH         : (950,870), t=8
%
% EVIDENCE BOUNDARY:
%   This is a circuit-software simulation evaluation. It does not establish
%   fabricated-silicon reliability or population joint min-entropy.

clc;
close all;

%% ========================================================================
% 1. CONFIGURATION
% =========================================================================

cfg.log_dir = 'RO_PUF_PVT_100';
cfg.log_pattern = 'chip_%03d_PVT.log';
cfg.challenge_file = 'challenge_schedule_balanced.csv';
cfg.output_dir = 'RO_PUF_PVT_100_results';

cfg.n_chips = 100;
cfg.n_ro = 128;
cfg.bank_size = 64;
cfg.n_candidate_bits = 1023;
cfg.n_expected_steps = 9;

cfg.nominal_vdd = 1.0;
cfg.nominal_temp_c = 25;

cfg.minimum_margin_percent = 0.500;
cfg.selected_response_length = 950;

cfg.parent_bch_length = 1023;
cfg.target_correction_t = 8;
cfg.parity_position = 'end';

cfg.tie_relative_tolerance = 1e-12;
cfg.maximum_edge100_ns = 40.0;

cfg.random_seed = 20260801;
cfg.kdf_label = 'RO-PUF-BCH-CODE-OFFSET-v1';

cfg.figure_visible = 'off';

if ~exist(cfg.output_dir, 'dir')
    mkdir(cfg.output_dir);
end

if ~exist(cfg.log_dir, 'dir')
    error('Log directory not found: %s', cfg.log_dir);
end

if ~isfile(cfg.challenge_file)
    error('Challenge schedule not found: %s', cfg.challenge_file);
end

%% ========================================================================
% 2. VERIFY COMMUNICATIONS TOOLBOX
% =========================================================================

required_functions = {'gf','bchnumerr','bchenc','bchdec'};
missing_functions = {};

for k = 1:numel(required_functions)
    if exist(required_functions{k}, 'file') == 0
        missing_functions{end+1} = required_functions{k}; %#ok<AGROW>
    end
end

if ~isempty(missing_functions)
    error(['Required Communications Toolbox functions are unavailable: %s. ' ...
           'Enable Communications Toolbox before running this analysis.'], ...
           strjoin(missing_functions, ', '));
end

%% ========================================================================
% 3. READ AND VALIDATE THE FROZEN CHALLENGE SCHEDULE
% =========================================================================

[first_ro_zero, second_ro_zero, challenge_index] = ...
    read_challenge_schedule(cfg.challenge_file, cfg.n_ro, cfg.bank_size);

if numel(first_ro_zero) ~= cfg.n_candidate_bits
    error('Expected %d challenges, but found %d.', ...
        cfg.n_candidate_bits, numel(first_ro_zero));
end

ordered_pairs = [first_ro_zero second_ro_zero];
unordered_pairs = sort(ordered_pairs, 2);

if size(unique(ordered_pairs, 'rows'),1) ~= cfg.n_candidate_bits
    error('The schedule contains duplicate ordered comparisons.');
end

if size(unique(unordered_pairs, 'rows'),1) ~= cfg.n_candidate_bits
    error('The schedule contains duplicate oscillator pairs.');
end

if any(first_ro_zero == second_ro_zero)
    error('The schedule contains self-comparisons.');
end

cross_bank = ...
    (first_ro_zero < cfg.bank_size & second_ro_zero >= cfg.bank_size) | ...
    (second_ro_zero < cfg.bank_size & first_ro_zero >= cfg.bank_size);

if ~all(cross_bank)
    error('Every comparison must contain one oscillator from each bank.');
end

a_first_count = sum(first_ro_zero < cfg.bank_size);
b_first_count = cfg.n_candidate_bits - a_first_count;

usage_count = accumarray( ...
    [first_ro_zero+1; second_ro_zero+1], 1, [cfg.n_ro 1]);

if ~isequal(sort([a_first_count b_first_count]), [511 512])
    warning('Expected a 511/512 orientation split, but found %d/%d.', ...
        a_first_count, b_first_count);
end

if min(usage_count) < 15 || max(usage_count) > 16
    warning('Expected each RO to be used 15-16 times; observed %d-%d.', ...
        min(usage_count), max(usage_count));
end

first_ro = first_ro_zero + 1;
second_ro = second_ro_zero + 1;

schedule_summary = table( ...
    cfg.n_candidate_bits, a_first_count, b_first_count, ...
    min(usage_count), max(usage_count), ...
    'VariableNames', {'response_positions','A_first_count', ...
    'B_first_count','minimum_RO_usage','maximum_RO_usage'});

writetable(schedule_summary, fullfile(cfg.output_dir, ...
    'challenge_schedule_validation.csv'));

fprintf('\nChallenge schedule validated:\n');
fprintf('  Response positions      : %d\n', cfg.n_candidate_bits);
fprintf('  A-first / B-first       : %d / %d\n', ...
    a_first_count, b_first_count);
fprintf('  Per-RO usage range      : %d-%d\n', ...
    min(usage_count), max(usage_count));

%% ========================================================================
% 4. SELECT THE BCH CODE
% =========================================================================

valid_bch = bchnumerr(cfg.parent_bch_length);

if size(valid_bch,2) ~= 3
    error('Unexpected bchnumerr output.');
end

eligible_codes = valid_bch( ...
    valid_bch(:,3) >= cfg.target_correction_t, :);

if isempty(eligible_codes)
    error('No valid BCH code meets t >= %d.', cfg.target_correction_t);
end

minimum_t = min(eligible_codes(:,3));
minimum_t_codes = eligible_codes(eligible_codes(:,3) == minimum_t,:);

[~, best_idx] = max(minimum_t_codes(:,2));
chosen = minimum_t_codes(best_idx,:);

bch.N_parent = chosen(1);
bch.K_parent = chosen(2);
bch.t_actual = chosen(3);
bch.redundancy = bch.N_parent - bch.K_parent;

bch.shortening = ...
    bch.N_parent - cfg.selected_response_length;

bch.N_short = bch.N_parent - bch.shortening;
bch.K_short = bch.K_parent - bch.shortening;

if bch.N_parent ~= 1023 || bch.K_parent ~= 943 || bch.t_actual ~= 8
    warning('Selected BCH parameters differ from the expected (1023,943), t=8.');
end

if bch.N_short ~= cfg.selected_response_length
    error('Shortened BCH length does not equal 950.');
end

fprintf('\nSelected parent BCH : (%d,%d), t=%d\n', ...
    bch.N_parent, bch.K_parent, bch.t_actual);

fprintf('Shortened BCH       : (%d,%d), t=%d\n', ...
    bch.N_short, bch.K_short, bch.t_actual);

%% ========================================================================
% 5. PREALLOCATE POPULATION DATA
% =========================================================================

n = cfg.n_chips;
m = cfg.n_candidate_bits;
selected_n = cfg.selected_response_length;

log_found = false(n,1);
log_valid = false(n,1);
failure_reason = repmat({''},n,1);

positions_meeting_threshold = nan(n,1);
enrollment_success = false(n,1);

selected_minimum_margin_percent = nan(n,1);
selected_median_margin_percent = nan(n,1);
selected_maximum_margin_percent = nan(n,1);

raw_worst_non_nominal_errors = nan(n,1);
raw_worst_non_nominal_ber_percent = nan(n,1);
raw_unstable_positions = nan(n,1);

selected_worst_non_nominal_errors = nan(n,1);
selected_worst_non_nominal_ber_percent = nan(n,1);
selected_conditions_exceeding_t = nan(n,1);

successful_non_nominal_reconstructions = zeros(n,1);
device_all_non_nominal_success = false(n,1);
all_conditions_key_match = false(n,1);

latest_edge100_ns = nan(n,1);

nominal_response_population = false(n,m);
selection_mask_population = false(n,m);
selected_indices_population = nan(n,selected_n);
helper_data_population = false(n,selected_n);

maximum_condition_rows = n * cfg.n_expected_steps;

condition_chip = nan(maximum_condition_rows,1);
condition_step = nan(maximum_condition_rows,1);
condition_vdd = nan(maximum_condition_rows,1);
condition_temp = nan(maximum_condition_rows,1);

condition_is_nominal = false(maximum_condition_rows,1);
condition_log_valid = false(maximum_condition_rows,1);
condition_enrollment_success = false(maximum_condition_rows,1);

condition_raw_errors = nan(maximum_condition_rows,1);
condition_raw_ber_percent = nan(maximum_condition_rows,1);

condition_selected_errors = nan(maximum_condition_rows,1);
condition_selected_ber_percent = nan(maximum_condition_rows,1);

condition_decoder_corrected = nan(maximum_condition_rows,1);
condition_decoder_failure = nan(maximum_condition_rows,1);
condition_message_match = nan(maximum_condition_rows,1);
condition_key_match = nan(maximum_condition_rows,1);
condition_reconstruction_success = zeros(maximum_condition_rows,1);

condition_max_edge100_ns = nan(maximum_condition_rows,1);

condition_row = 0;
reference_pvt = table();

selftest_completed = false;
selftest_corrected_errors = NaN;

%% ========================================================================
% 6. PROCESS ALL 100 LOG FILES
% =========================================================================

fprintf('\nProcessing %d fixed-mismatch PVT devices...\n\n', n);

for chip = 1:n

    log_name = sprintf(cfg.log_pattern, chip);
    log_file = fullfile(cfg.log_dir, log_name);

    log_found(chip) = isfile(log_file);

    if ~log_found(chip)
        failure_reason{chip} = 'Log file not found';
        fprintf('[%03d/%03d] MISSING: %s\n', chip, n, log_file);
        continue;
    end

    try
        [pvt, freq_matrix, edge_matrix, parse_report] = ...
            parse_pvt_ltspice_log(log_file, cfg.n_ro);

        if height(pvt) ~= cfg.n_expected_steps
            error('Expected %d PVT steps; found %d.', ...
                cfg.n_expected_steps, height(pvt));
        end

        if parse_report.frequency_blocks_found ~= cfg.n_ro
            error('Expected 128 frequency blocks; found %d.', ...
                parse_report.frequency_blocks_found);
        end

        if parse_report.edge100_blocks_found ~= cfg.n_ro
            error('Expected 128 edge blocks; found %d.', ...
                parse_report.edge100_blocks_found);
        end

        if any(~isfinite(freq_matrix(:))) || any(freq_matrix(:) <= 0)
            error('Missing or invalid frequency measurements.');
        end

        if any(~isfinite(edge_matrix(:))) || any(edge_matrix(:) <= 0)
            error('Missing or invalid edge-100 measurements.');
        end

        latest_edge100_ns(chip) = max(edge_matrix(:)) * 1e9;

        if latest_edge100_ns(chip) >= cfg.maximum_edge100_ns
            error('Latest edge %.6f ns reaches/exceeds the %.3f ns limit.', ...
                latest_edge100_ns(chip), cfg.maximum_edge100_ns);
        end

        if isempty(reference_pvt)
            reference_pvt = pvt;
        else
            if any(abs(reference_pvt.vdd_v-pvt.vdd_v) > 1e-12) || ...
                    any(abs(reference_pvt.temp_c-pvt.temp_c) > 1e-12)
                error('PVT grid differs from the first valid device.');
            end
        end

        first_freq = freq_matrix(:,first_ro);
        second_freq = freq_matrix(:,second_ro);

        mean_pair_frequency = (first_freq + second_freq) / 2;

        relative_margin = ...
            abs(first_freq-second_freq) ./ mean_pair_frequency;

        if any(relative_margin(:) <= cfg.tie_relative_tolerance)
            error('Frequency tie or numerically indistinguishable comparison found.');
        end

        response = first_freq > second_freq;

        nominal_candidates = find( ...
            abs(pvt.vdd_v-cfg.nominal_vdd) < 1e-12 & ...
            abs(pvt.temp_c-cfg.nominal_temp_c) < 1e-12);

        if numel(nominal_candidates) ~= 1
            error('Expected exactly one nominal 1.0 V, 25 C condition.');
        end

        nominal_row = nominal_candidates(1);
        nominal_response = response(nominal_row,:);

        nominal_response_population(chip,:) = nominal_response;

        non_nominal = true(height(pvt),1);
        non_nominal(nominal_row) = false;

        raw_flip_matrix = xor(response, nominal_response);
        raw_error_count = sum(raw_flip_matrix,2);
        raw_ber_percent = ...
            100 * raw_error_count / cfg.n_candidate_bits;

        raw_worst_non_nominal_errors(chip) = ...
            max(raw_error_count(non_nominal));

        raw_worst_non_nominal_ber_percent(chip) = ...
            max(raw_ber_percent(non_nominal));

        raw_unstable_positions(chip) = ...
            sum(any(raw_flip_matrix(non_nominal,:),1));

        nominal_margin_percent = ...
            100 * relative_margin(nominal_row,:);

        eligible = ...
            nominal_margin_percent >= cfg.minimum_margin_percent;

        positions_meeting_threshold(chip) = sum(eligible);

        selected_error_count = nan(height(pvt),1);
        selected_ber_percent = nan(height(pvt),1);

        decoder_corrected = nan(height(pvt),1);
        decoder_failure = nan(height(pvt),1);
        message_match = nan(height(pvt),1);
        key_match = nan(height(pvt),1);
        reconstruction_success = zeros(height(pvt),1);

        if positions_meeting_threshold(chip) >= ...
                cfg.selected_response_length

            enrollment_success(chip) = true;

            challenge_one_based = (1:cfg.n_candidate_bits)';

            ranking_matrix = [ ...
                -nominal_margin_percent(:), ...
                challenge_one_based];

            [~, ranked_order] = sortrows(ranking_matrix,[1 2]);

            selected_one_based = ...
                sort(ranked_order(1:cfg.selected_response_length));

            selected_zero_based = selected_one_based - 1;

            selected_indices_population(chip,:) = ...
                selected_zero_based(:)';

            selection_mask = false(1,cfg.n_candidate_bits);
            selection_mask(selected_one_based) = true;

            selection_mask_population(chip,:) = selection_mask;

            selected_margins = ...
                nominal_margin_percent(selected_one_based);

            selected_minimum_margin_percent(chip) = ...
                min(selected_margins);

            selected_median_margin_percent(chip) = ...
                median(selected_margins);

            selected_maximum_margin_percent(chip) = ...
                max(selected_margins);

            enrolled_response = ...
                nominal_response(selected_one_based);

            selected_responses_all = ...
                response(:,selected_one_based);

            selected_flip_matrix = ...
                xor(selected_responses_all,enrolled_response);

            selected_error_count = ...
                sum(selected_flip_matrix,2);

            selected_ber_percent = ...
                100 * selected_error_count / ...
                cfg.selected_response_length;

            selected_worst_non_nominal_errors(chip) = ...
                max(selected_error_count(non_nominal));

            selected_worst_non_nominal_ber_percent(chip) = ...
                max(selected_ber_percent(non_nominal));

            selected_conditions_exceeding_t(chip) = ...
                sum(selected_error_count(non_nominal) > ...
                bch.t_actual);

            stream = RandStream('mt19937ar', ...
                'Seed', cfg.random_seed + chip - 1);

            enrolled_message = ...
                rand(stream,1,bch.K_short) >= 0.5;

            parent_message = [ ...
                false(1,bch.shortening), enrolled_message];

            parent_code_gf = bchenc( ...
                gf(double(parent_message)), ...
                bch.N_parent, bch.K_parent, ...
                cfg.parity_position);

            parent_code = logical(parent_code_gf.x);

            if ~isequal(parent_code(1:bch.K_parent), ...
                    parent_message)
                error('BCH encoder is not systematic with parity at the end.');
            end

            shortened_codeword = ...
                parent_code(bch.shortening+1:end);

            helper_data = ...
                xor(enrolled_response,shortened_codeword);

            helper_data_population(chip,:) = helper_data;

            chip_id_text = sprintf('chip_%03d',chip);

            kdf_context = sprintf( ...
                '%s|%s|N%d|K%d|NS%d|KS%d|t%d', ...
                cfg.kdf_label, chip_id_text, ...
                bch.N_parent, bch.K_parent, ...
                bch.N_short, bch.K_short, ...
                bch.t_actual);

            enrolled_key_hex = ...
                derive_sha256_key(enrolled_message,kdf_context);

            if ~selftest_completed
                test_positions = randperm( ...
                    stream,bch.N_short,bch.t_actual);

                test_received = shortened_codeword;
                test_received(test_positions) = ...
                    ~test_received(test_positions);

                [test_message,test_corrected,test_failure] = ...
                    decode_shortened_bch( ...
                    test_received,bch,cfg.parity_position);

                if test_failure || ...
                        ~isequal(test_message,enrolled_message)
                    error('Shortened BCH self-test failed.');
                end

                selftest_completed = true;
                selftest_corrected_errors = test_corrected;
            end

            for step = 1:height(pvt)

                noisy_response = ...
                    selected_responses_all(step,:);

                received_short = ...
                    xor(noisy_response,helper_data);

                [recovered_message,num_corrected, ...
                    decoder_failed] = ...
                    decode_shortened_bch( ...
                    received_short,bch, ...
                    cfg.parity_position);

                recovered_key_hex = ...
                    derive_sha256_key( ...
                    recovered_message,kdf_context);

                decoder_corrected(step) = num_corrected;
                decoder_failure(step) = decoder_failed;

                message_match(step) = ...
                    isequal(recovered_message,enrolled_message);

                key_match(step) = ...
                    strcmp(recovered_key_hex,enrolled_key_hex);

                reconstruction_success(step) = ...
                    message_match(step) && ...
                    key_match(step) && ...
                    ~decoder_failed;
            end

            successful_non_nominal_reconstructions(chip) = ...
                sum(reconstruction_success(non_nominal));

            device_all_non_nominal_success(chip) = ...
                all(reconstruction_success(non_nominal));

            all_conditions_key_match(chip) = ...
                all(reconstruction_success);

        else
            enrollment_success(chip) = false;
            selected_conditions_exceeding_t(chip) = NaN;
        end

        log_valid(chip) = true;

        for step = 1:height(pvt)
            condition_row = condition_row + 1;

            condition_chip(condition_row) = chip;
            condition_step(condition_row) = pvt.step_id(step);
            condition_vdd(condition_row) = pvt.vdd_v(step);
            condition_temp(condition_row) = pvt.temp_c(step);

            condition_is_nominal(condition_row) = ...
                step == nominal_row;

            condition_log_valid(condition_row) = true;

            condition_enrollment_success(condition_row) = ...
                enrollment_success(chip);

            condition_raw_errors(condition_row) = ...
                raw_error_count(step);

            condition_raw_ber_percent(condition_row) = ...
                raw_ber_percent(step);

            condition_selected_errors(condition_row) = ...
                selected_error_count(step);

            condition_selected_ber_percent(condition_row) = ...
                selected_ber_percent(step);

            condition_decoder_corrected(condition_row) = ...
                decoder_corrected(step);

            condition_decoder_failure(condition_row) = ...
                decoder_failure(step);

            condition_message_match(condition_row) = ...
                message_match(step);

            condition_key_match(condition_row) = ...
                key_match(step);

            condition_reconstruction_success(condition_row) = ...
                reconstruction_success(step);

            condition_max_edge100_ns(condition_row) = ...
                max(edge_matrix(step,:))*1e9;
        end

        if mod(chip,10) == 0 || chip == 1
            fprintf(['[%03d/%03d] valid; eligible=%d; ' ...
                'raw worst=%d; selected worst=%s; ' ...
                'key success=%d/8\n'], ...
                chip,n,positions_meeting_threshold(chip), ...
                raw_worst_non_nominal_errors(chip), ...
                number_text(selected_worst_non_nominal_errors(chip)), ...
                successful_non_nominal_reconstructions(chip));
        end

    catch ME
        log_valid(chip) = false;
        failure_reason{chip} = ME.message;

        fprintf('[%03d/%03d] INVALID: %s\n', ...
            chip,n,ME.message);
    end
end

%% ========================================================================
% 7. BUILD THE CHIP-LEVEL SUMMARY
% =========================================================================

chip_id = (1:n)';

chip_summary = table( ...
    chip_id,log_found,log_valid,failure_reason, ...
    positions_meeting_threshold,enrollment_success, ...
    selected_minimum_margin_percent, ...
    selected_median_margin_percent, ...
    selected_maximum_margin_percent, ...
    raw_worst_non_nominal_errors, ...
    raw_worst_non_nominal_ber_percent, ...
    raw_unstable_positions, ...
    selected_worst_non_nominal_errors, ...
    selected_worst_non_nominal_ber_percent, ...
    selected_conditions_exceeding_t, ...
    successful_non_nominal_reconstructions, ...
    device_all_non_nominal_success, ...
    all_conditions_key_match,latest_edge100_ns);

writetable(chip_summary,fullfile(cfg.output_dir, ...
    'PVT_100_chip_summary.csv'));

%% ========================================================================
% 8. BUILD THE CONDITION-LEVEL TABLE
% =========================================================================

used = 1:condition_row;

condition_table = table( ...
    condition_chip(used), ...
    condition_step(used), ...
    condition_vdd(used), ...
    condition_temp(used), ...
    condition_is_nominal(used), ...
    condition_log_valid(used), ...
    condition_enrollment_success(used), ...
    condition_raw_errors(used), ...
    condition_raw_ber_percent(used), ...
    condition_selected_errors(used), ...
    condition_selected_ber_percent(used), ...
    condition_decoder_corrected(used), ...
    condition_decoder_failure(used), ...
    condition_message_match(used), ...
    condition_key_match(used), ...
    condition_reconstruction_success(used), ...
    condition_max_edge100_ns(used), ...
    'VariableNames', { ...
    'chip_id','step_id','vdd_v','temp_c', ...
    'is_nominal','log_valid','enrollment_success', ...
    'raw_response_errors','raw_ber_percent', ...
    'selected_response_errors','selected_ber_percent', ...
    'decoder_reported_corrected_errors', ...
    'decoder_reported_failure','message_match', ...
    'key_match','reconstruction_success', ...
    'max_edge100_ns'});

writetable(condition_table,fullfile(cfg.output_dir, ...
    'PVT_100_condition_results.csv'));

%% ========================================================================
% 9. CORNER-BY-CORNER SUMMARY
% =========================================================================

if isempty(reference_pvt)
    error('No valid PVT logs were available.');
end

corner_count = height(reference_pvt);

corner_mean_raw_errors = nan(corner_count,1);
corner_median_raw_errors = nan(corner_count,1);
corner_worst_raw_errors = nan(corner_count,1);

corner_mean_selected_errors = nan(corner_count,1);
corner_median_selected_errors = nan(corner_count,1);
corner_p95_selected_errors = nan(corner_count,1);
corner_p99_selected_errors = nan(corner_count,1);
corner_worst_selected_errors = nan(corner_count,1);

corner_enrolled_attempts = zeros(corner_count,1);
corner_successful_reconstructions = zeros(corner_count,1);
corner_success_percent_executed = nan(corner_count,1);
corner_success_percent_conservative = nan(corner_count,1);

for step = 1:corner_count

    mask = ...
        abs(condition_table.vdd_v-reference_pvt.vdd_v(step)) < 1e-12 & ...
        abs(condition_table.temp_c-reference_pvt.temp_c(step)) < 1e-12;

    raw_values = ...
        condition_table.raw_response_errors(mask);

    selected_values = ...
        condition_table.selected_response_errors(mask);

    selected_values = ...
        selected_values(isfinite(selected_values));

    corner_mean_raw_errors(step) = finite_mean(raw_values);
    corner_median_raw_errors(step) = finite_median(raw_values);
    corner_worst_raw_errors(step) = finite_max(raw_values);

    corner_mean_selected_errors(step) = ...
        finite_mean(selected_values);

    corner_median_selected_errors(step) = ...
        finite_median(selected_values);

    corner_p95_selected_errors(step) = ...
        percentile_value(selected_values,95);

    corner_p99_selected_errors(step) = ...
        percentile_value(selected_values,99);

    corner_worst_selected_errors(step) = ...
        finite_max(selected_values);

    corner_enrolled_attempts(step) = ...
        sum(condition_table.enrollment_success(mask));

    corner_successful_reconstructions(step) = ...
        sum(condition_table.reconstruction_success(mask) == 1);

    if corner_enrolled_attempts(step) > 0
        corner_success_percent_executed(step) = ...
            100 * corner_successful_reconstructions(step) / ...
            corner_enrolled_attempts(step);
    end

    corner_success_percent_conservative(step) = ...
        100 * corner_successful_reconstructions(step) / ...
        cfg.n_chips;
end

corner_summary = table( ...
    reference_pvt.step_id,reference_pvt.vdd_v, ...
    reference_pvt.temp_c, ...
    corner_mean_raw_errors,corner_median_raw_errors, ...
    corner_worst_raw_errors, ...
    corner_mean_selected_errors, ...
    corner_median_selected_errors, ...
    corner_p95_selected_errors, ...
    corner_p99_selected_errors, ...
    corner_worst_selected_errors, ...
    corner_enrolled_attempts, ...
    corner_successful_reconstructions, ...
    corner_success_percent_executed, ...
    corner_success_percent_conservative, ...
    'VariableNames', { ...
    'step_id','vdd_v','temp_c', ...
    'mean_raw_errors','median_raw_errors', ...
    'worst_raw_errors','mean_selected_errors', ...
    'median_selected_errors','p95_selected_errors', ...
    'p99_selected_errors','worst_selected_errors', ...
    'enrolled_attempts','successful_reconstructions', ...
    'success_percent_among_enrolled', ...
    'success_percent_out_of_100_devices'});

writetable(corner_summary,fullfile(cfg.output_dir, ...
    'PVT_100_corner_summary.csv'));

%% ========================================================================
% 10. NOMINAL INTER-DEVICE HD AND BIT ALIAS
% =========================================================================

valid_devices = find(log_valid);

[raw_hd_percent,raw_hd_device_1,raw_hd_device_2] = ...
    calculate_interdevice_hd( ...
    nominal_response_population(valid_devices,:), ...
    valid_devices);

raw_hd_table = table( ...
    raw_hd_device_1,raw_hd_device_2,raw_hd_percent, ...
    'VariableNames', {'chip_1','chip_2','raw_nominal_HD_percent'});

writetable(raw_hd_table,fullfile(cfg.output_dir, ...
    'PVT_100_nominal_interdevice_HD.csv'));

if ~isempty(valid_devices)
    nominal_bit_alias_percent = ...
        100 * mean(nominal_response_population(valid_devices,:),1)';
else
    nominal_bit_alias_percent = nan(m,1);
end

bit_alias_table = table( ...
    challenge_index(:),nominal_bit_alias_percent, ...
    'VariableNames', {'challenge_index','bit_alias_percent'});

writetable(bit_alias_table,fullfile(cfg.output_dir, ...
    'PVT_100_nominal_bit_alias.csv'));

%% ========================================================================
% 11. MUTUAL-SELECTED INTER-DEVICE HD
% =========================================================================

enrolled_devices = find(enrollment_success & log_valid);

[mutual_hd_percent,mutual_position_count, ...
    mutual_device_1,mutual_device_2] = ...
    calculate_mutual_selected_hd( ...
    nominal_response_population, ...
    selection_mask_population, ...
    enrolled_devices);

mutual_hd_table = table( ...
    mutual_device_1,mutual_device_2, ...
    mutual_position_count,mutual_hd_percent, ...
    'VariableNames', {'chip_1','chip_2', ...
    'mutually_selected_positions', ...
    'mutual_selected_HD_percent'});

writetable(mutual_hd_table,fullfile(cfg.output_dir, ...
    'PVT_100_mutual_selected_HD.csv'));

%% ========================================================================
% 12. POPULATION-LEVEL SUMMARY
% =========================================================================

valid_log_count = sum(log_valid);
enrollment_count = sum(enrollment_success);

device_success_count = ...
    sum(device_all_non_nominal_success);

expected_non_nominal_attempts = ...
    cfg.n_chips * (cfg.n_expected_steps-1);

executed_non_nominal_mask = ...
    ~condition_table.is_nominal & ...
    condition_table.enrollment_success;

executed_non_nominal_attempts = ...
    sum(executed_non_nominal_mask);

successful_non_nominal_attempts = ...
    sum(condition_table.reconstruction_success( ...
    ~condition_table.is_nominal) == 1);

failed_or_unexecuted_attempts = ...
    expected_non_nominal_attempts - ...
    successful_non_nominal_attempts;

[enrollment_ci_low,enrollment_ci_high] = ...
    wilson_interval(enrollment_count,cfg.n_chips,0.05);

[device_ci_low,device_ci_high] = ...
    wilson_interval(device_success_count,cfg.n_chips,0.05);

if executed_non_nominal_attempts > 0
    [attempt_ci_low,attempt_ci_high] = ...
        wilson_interval( ...
        successful_non_nominal_attempts, ...
        executed_non_nominal_attempts,0.05);
else
    attempt_ci_low = NaN;
    attempt_ci_high = NaN;
end

selected_non_nominal_errors = ...
    condition_table.selected_response_errors( ...
    ~condition_table.is_nominal & ...
    isfinite(condition_table.selected_response_errors));

conditions_exceeding_t = ...
    sum(selected_non_nominal_errors > bch.t_actual);

device_failure_upper95_if_zero = NaN;

if device_success_count == cfg.n_chips
    device_failure_upper95_if_zero = ...
        1 - 0.05^(1/cfg.n_chips);
end

condition_failure_upper95_if_zero = NaN;

if successful_non_nominal_attempts == ...
        expected_non_nominal_attempts

    condition_failure_upper95_if_zero = ...
        1 - 0.05^(1/expected_non_nominal_attempts);
end

population_summary = table( ...
    cfg.n_chips,valid_log_count,enrollment_count, ...
    100*enrollment_count/cfg.n_chips, ...
    100*enrollment_ci_low,100*enrollment_ci_high, ...
    device_success_count, ...
    100*device_success_count/cfg.n_chips, ...
    100*device_ci_low,100*device_ci_high, ...
    expected_non_nominal_attempts, ...
    executed_non_nominal_attempts, ...
    successful_non_nominal_attempts, ...
    failed_or_unexecuted_attempts, ...
    100*successful_non_nominal_attempts / ...
        expected_non_nominal_attempts, ...
    100*attempt_ci_low,100*attempt_ci_high, ...
    finite_mean(positions_meeting_threshold), ...
    finite_median(positions_meeting_threshold), ...
    finite_min(positions_meeting_threshold), ...
    finite_max(positions_meeting_threshold), ...
    finite_max(raw_worst_non_nominal_errors), ...
    finite_max(selected_worst_non_nominal_errors), ...
    percentile_value(selected_non_nominal_errors,95), ...
    percentile_value(selected_non_nominal_errors,99), ...
    conditions_exceeding_t, ...
    finite_max(latest_edge100_ns), ...
    finite_mean(raw_hd_percent), ...
    finite_median(raw_hd_percent), ...
    finite_mean(mutual_hd_percent), ...
    finite_mean(mutual_position_count), ...
    bch.N_parent,bch.K_parent,bch.N_short,bch.K_short, ...
    bch.t_actual,bch.redundancy, ...
    selftest_corrected_errors, ...
    100*device_failure_upper95_if_zero, ...
    100*condition_failure_upper95_if_zero, ...
    'VariableNames', { ...
    'expected_devices','valid_logs','enrolled_devices', ...
    'enrollment_yield_percent', ...
    'enrollment_Wilson95_low_percent', ...
    'enrollment_Wilson95_high_percent', ...
    'devices_passing_all_8_non_nominal_conditions', ...
    'device_success_percent', ...
    'device_success_Wilson95_low_percent', ...
    'device_success_Wilson95_high_percent', ...
    'expected_non_nominal_attempts', ...
    'executed_non_nominal_attempts', ...
    'successful_non_nominal_reconstructions', ...
    'failed_or_unexecuted_non_nominal_attempts', ...
    'conservative_non_nominal_success_percent', ...
    'executed_attempt_Wilson95_low_percent', ...
    'executed_attempt_Wilson95_high_percent', ...
    'mean_positions_meeting_0p5_percent', ...
    'median_positions_meeting_0p5_percent', ...
    'minimum_positions_meeting_0p5_percent', ...
    'maximum_positions_meeting_0p5_percent', ...
    'worst_raw_non_nominal_errors', ...
    'worst_selected_non_nominal_errors', ...
    'selected_error_count_p95', ...
    'selected_error_count_p99', ...
    'selected_conditions_exceeding_t8', ...
    'latest_edge100_ns', ...
    'mean_raw_nominal_interdevice_HD_percent', ...
    'median_raw_nominal_interdevice_HD_percent', ...
    'mean_mutual_selected_HD_percent', ...
    'mean_mutually_selected_positions', ...
    'parent_BCH_N','parent_BCH_K', ...
    'shortened_BCH_N','shortened_BCH_K', ...
    'BCH_t','BCH_redundancy_bits', ...
    'BCH_selftest_corrected_errors', ...
    'zero_observed_device_failure_upper95_percent', ...
    'zero_observed_condition_failure_upper95_percent'});

writetable(population_summary,fullfile(cfg.output_dir, ...
    'PVT_100_population_summary.csv'));

%% ========================================================================
% 13. GENERATE PAPER-READY FIGURES
% =========================================================================

create_population_figures( ...
    cfg,chip_summary,condition_table,corner_summary, ...
    raw_hd_percent);

%% ========================================================================
% 14. SAVE COMPLETE MATLAB WORKSPACE
% =========================================================================

save(fullfile(cfg.output_dir, ...
    'PVT_100_population_results.mat'), ...
    'cfg','bch','schedule_summary','chip_summary', ...
    'condition_table','corner_summary','population_summary', ...
    'nominal_response_population','selection_mask_population', ...
    'selected_indices_population','helper_data_population', ...
    'raw_hd_table','bit_alias_table','mutual_hd_table', ...
    '-v7.3');

%% ========================================================================
% 15. PRINT FINAL SUMMARY
% =========================================================================

fprintf('\n');
fprintf('================ 100-DEVICE PVT POPULATION SUMMARY ================\n');
fprintf('Expected fixed-mismatch devices          : %d\n',cfg.n_chips);
fprintf('Valid logs                               : %d\n',valid_log_count);
fprintf('Successfully enrolled devices            : %d\n',enrollment_count);
fprintf('Enrollment yield                         : %.3f %%\n', ...
    100*enrollment_count/cfg.n_chips);

fprintf('Devices passing all 8 PVT corners        : %d of %d\n', ...
    device_success_count,cfg.n_chips);

fprintf('Successful non-nominal key matches       : %d of %d\n', ...
    successful_non_nominal_attempts, ...
    expected_non_nominal_attempts);

fprintf('Worst raw non-nominal error count        : %.0f\n', ...
    finite_max(raw_worst_non_nominal_errors));

fprintf('Worst selected non-nominal error count   : %.0f\n', ...
    finite_max(selected_worst_non_nominal_errors));

fprintf('Selected conditions exceeding BCH t=8   : %d\n', ...
    conditions_exceeding_t);

fprintf('Latest observed 100th edge               : %.4f ns\n', ...
    finite_max(latest_edge100_ns));

fprintf('Mean raw nominal inter-device HD         : %.3f %%\n', ...
    finite_mean(raw_hd_percent));

fprintf('Mean mutual-selected inter-device HD     : %.3f %%\n', ...
    finite_mean(mutual_hd_percent));

fprintf('BCH self-test corrected errors           : %.0f\n', ...
    selftest_corrected_errors);

fprintf('Output directory                         : %s\n', ...
    cfg.output_dir);

fprintf('\nInterpretation boundary:\n');
fprintf(['These values characterize 100 fixed-mismatch simulated devices under\n' ...
         'the evaluated nine-condition PVT grid. They do not establish\n' ...
         'fabricated-silicon reliability, physical unclonability, or joint\n' ...
         'conditional min-entropy.\n']);

fprintf('====================================================================\n');

disp(population_summary);

end

%% =========================================================================
% LOCAL FUNCTION: LTSPICE LOG PARSER
% =========================================================================

function [pvt,freq_matrix,edge_matrix,report] = ...
    parse_pvt_ltspice_log(log_file,n_ro)

text = fileread(log_file);
text_lower = lower(text);

failure_patterns = { ...
    'measurement failed', ...
    'target not found', ...
    'trigger not found', ...
    'voltage not found', ...
    'time step too small', ...
    'fatal error', ...
    'singular matrix'};

for k = 1:numel(failure_patterns)
    if contains(text_lower,failure_patterns{k})
        error('LTspice failure text found: "%s".', ...
            failure_patterns{k});
    end
end

lines = regexp(text,'\r\n|\n|\r','split');

step_vdd = [];
step_temp = [];

for i = 1:numel(lines)

    token = regexp(lines{i}, ...
        ['^\s*\.step\s+vddval=' ...
         '([+\-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+\-]?\d+)?)\s+' ...
         'temp=([+\-]?(?:\d+\.?\d*|\.\d+)' ...
         '(?:[eE][+\-]?\d+)?)'], ...
        'tokens','once','ignorecase');

    if ~isempty(token)
        step_vdd(end+1,1) = str2double(token{1}); %#ok<AGROW>
        step_temp(end+1,1) = str2double(token{2}); %#ok<AGROW>
    end
end

if isempty(step_vdd)
    error('No PVT .step conditions were found.');
end

n_steps = numel(step_vdd);

pvt = table( ...
    (1:n_steps)',step_vdd,step_temp, ...
    'VariableNames',{'step_id','vdd_v','temp_c'});

freq_matrix = nan(n_steps,n_ro);
edge_matrix = nan(n_steps,n_ro);

frequency_blocks = false(1,n_ro);
edge_blocks = false(1,n_ro);

current_type = '';
current_ro = NaN;

for i = 1:numel(lines)

    line = lines{i};

    token = regexp(line, ...
        '^\s*Measurement:\s*freq_ro(\d+)\s*$', ...
        'tokens','once','ignorecase');

    if ~isempty(token)
        current_type = 'frequency';
        current_ro = str2double(token{1});

        if current_ro >= 0 && current_ro < n_ro
            frequency_blocks(current_ro+1) = true;
        end

        continue;
    end

    token = regexp(line, ...
        '^\s*Measurement:\s*edge100_ro(\d+)\s*$', ...
        'tokens','once','ignorecase');

    if ~isempty(token)
        current_type = 'edge';
        current_ro = str2double(token{1});

        if current_ro >= 0 && current_ro < n_ro
            edge_blocks(current_ro+1) = true;
        end

        continue;
    end

    if startsWith(strtrim(line),'Measurement:', ...
            'IgnoreCase',true)
        current_type = '';
        current_ro = NaN;
        continue;
    end

    if isempty(current_type) || ...
            ~isfinite(current_ro) || ...
            current_ro < 0 || current_ro >= n_ro
        continue;
    end

    value_token = regexp(line, ...
        ['^\s*(\d+)\s+' ...
         '([+\-]?(?:\d+\.?\d*|\.\d+)' ...
         '(?:[eE][+\-]?\d+)?)\s*$'], ...
        'tokens','once');

    if isempty(value_token)
        continue;
    end

    step_id = str2double(value_token{1});
    value = str2double(value_token{2});

    if step_id < 1 || step_id > n_steps
        continue;
    end

    if strcmp(current_type,'frequency')
        freq_matrix(step_id,current_ro+1) = value;
    else
        edge_matrix(step_id,current_ro+1) = value;
    end
end

report.n_steps = n_steps;
report.frequency_blocks_found = sum(frequency_blocks);
report.edge100_blocks_found = sum(edge_blocks);
report.missing_frequency_blocks = find(~frequency_blocks)-1;
report.missing_edge_blocks = find(~edge_blocks)-1;

end

%% =========================================================================
% LOCAL FUNCTION: CHALLENGE-SCHEDULE READER
% =========================================================================

function [first_zero,second_zero,challenge_index] = ...
    read_challenge_schedule(file_name,n_ro,bank_size)

try
    T = readtable(file_name,'VariableNamingRule','preserve');
catch
    T = readtable(file_name,'PreserveVariableNames',true);
end

names = T.Properties.VariableNames;
normalized_names = cell(size(names));

for k = 1:numel(names)
    normalized_names{k} = lower( ...
        regexprep(char(names{k}),'[^a-zA-Z0-9]',''));
end

idx_challenge = find_alias(normalized_names, ...
    {'challengeindex','challenge','bitindex','responseindex'});

idx_first = find_alias(normalized_names, ...
    {'firstglobalroindex','firstglobalro','firstroindex','firstro'});

idx_second = find_alias(normalized_names, ...
    {'secondglobalroindex','secondglobalro','secondroindex','secondro'});

if ~isempty(idx_first) && ~isempty(idx_second)

    first_zero = normalize_global_indices( ...
        double(T{:,idx_first}),n_ro,'first oscillator');

    second_zero = normalize_global_indices( ...
        double(T{:,idx_second}),n_ro,'second oscillator');

else
    idx_global_a = find_alias(normalized_names, ...
        {'globalroaindex','globalroa','roaglobalindex'});

    idx_global_b = find_alias(normalized_names, ...
        {'globalrobindex','globalrob','robglobalindex'});

    idx_local_a = find_alias(normalized_names, ...
        {'bankaindex','bankaroindex','roaindex','roa'});

    idx_local_b = find_alias(normalized_names, ...
        {'bankbindex','bankbroindex','robindex','rob'});

    idx_orientation = find_alias(normalized_names, ...
        {'orientationcode','orientation','direction', ...
         'comparisondirection'});

    if isempty(idx_orientation)
        error(['The schedule does not contain oriented first/second columns ' ...
               'or an orientation column. Use the final balanced ' ...
               'challenge_schedule.csv.']);
    end

    orientation = parse_orientation(T{:,idx_orientation});

    if ~isempty(idx_global_a) && ~isempty(idx_global_b)

        a_zero = normalize_global_indices( ...
            double(T{:,idx_global_a}),n_ro,'Bank-A oscillator');

        b_zero = normalize_global_indices( ...
            double(T{:,idx_global_b}),n_ro,'Bank-B oscillator');

    elseif ~isempty(idx_local_a) && ~isempty(idx_local_b)

        a_zero = normalize_bank_indices( ...
            double(T{:,idx_local_a}),bank_size,'Bank A');

        b_local = normalize_bank_indices( ...
            double(T{:,idx_local_b}),bank_size,'Bank B');

        b_zero = bank_size + b_local;

    else
        error('Unrecognized challenge-schedule columns.');
    end

    first_zero = a_zero;
    second_zero = b_zero;

    reverse = orientation < 0;

    first_zero(reverse) = b_zero(reverse);
    second_zero(reverse) = a_zero(reverse);
end

if isempty(idx_challenge)
    challenge_index = (0:height(T)-1)';
else
    challenge_index = double(T{:,idx_challenge});

    if all(challenge_index >= 1) && ...
            max(challenge_index) == height(T) && ...
            ~any(challenge_index == 0)
        challenge_index = challenge_index - 1;
    end
end

first_zero = first_zero(:);
second_zero = second_zero(:);
challenge_index = challenge_index(:);

end

function idx = find_alias(normalized_names,aliases)

idx = [];

for k = 1:numel(aliases)
    candidate = find(strcmp(normalized_names,aliases{k}),1);

    if ~isempty(candidate)
        idx = candidate;
        return;
    end
end

end

function zero_based = ...
    normalize_global_indices(values,n_ro,label)

values = values(:);

if all(values >= 0 & values < n_ro)
    zero_based = values;

elseif all(values >= 1 & values <= n_ro) && ...
        any(values == n_ro) && ~any(values == 0)

    warning('One-based %s indices detected.',label);
    zero_based = values - 1;

else
    error('%s indices are outside the valid range.',label);
end

end

function zero_based = ...
    normalize_bank_indices(values,bank_size,label)

values = values(:);

if all(values >= 0 & values < bank_size)
    zero_based = values;

elseif all(values >= 1 & values <= bank_size) && ...
        any(values == bank_size) && ~any(values == 0)

    warning('One-based %s indices detected.',label);
    zero_based = values - 1;

else
    error('%s indices are outside the valid bank range.',label);
end

end

function orientation = parse_orientation(raw)

if isnumeric(raw) || islogical(raw)

    values = double(raw(:));
    unique_values = unique(values(isfinite(values)));

    if all(ismember(unique_values,[-1 1]))
        orientation = values;

    elseif all(ismember(unique_values,[0 1]))
        orientation = ones(size(values));
        orientation(values == 0) = -1;

    else
        error('Numeric orientation must use +1/-1 or 1/0.');
    end

else
    values = string(raw(:));
    orientation = nan(numel(values),1);

    for k = 1:numel(values)

        token = lower(regexprep(strtrim(values(k)),'\s+',''));

        if any(token == ["a>b","agtb","+1","forward","ab"])
            orientation(k) = 1;

        elseif any(token == ["b>a","bgta","-1","reverse","ba"])
            orientation(k) = -1;
        end
    end

    if any(~isfinite(orientation))
        error('Unrecognized orientation text.');
    end
end

end

%% =========================================================================
% LOCAL FUNCTION: SHORTENED BCH DECODER
% =========================================================================

function [message_short,num_corrected,decoder_failure] = ...
    decode_shortened_bch(received_short,bch,parity_position)

received_parent = [ ...
    false(1,bch.shortening), ...
    logical(received_short)];

[decoded_parent_gf,num_corrected] = bchdec( ...
    gf(double(received_parent)), ...
    bch.N_parent,bch.K_parent, ...
    parity_position);

decoded_parent = logical(decoded_parent_gf.x);

message_short = ...
    decoded_parent(bch.shortening+1:end);

decoder_failure = num_corrected < 0;

end

%% =========================================================================
% LOCAL FUNCTION: SHA-256 KDF
% =========================================================================

function key_hex = derive_sha256_key(message_bits,context)

packed = pack_bits_msb_first(logical(message_bits));

bit_length = uint32(numel(message_bits));
mask255 = uint32(255);

length_bytes = uint8([ ...
    bitand(bitshift(bit_length,-24),mask255), ...
    bitand(bitshift(bit_length,-16),mask255), ...
    bitand(bitshift(bit_length,-8),mask255), ...
    bitand(bit_length,mask255)]);

data = [ ...
    length_bytes(:); ...
    packed(:); ...
    uint8(context(:))];

md = javaMethod( ...
    'getInstance', ...
    'java.security.MessageDigest', ...
    'SHA-256');

md.update(typecast(uint8(data),'int8'));

raw = md.digest();

digest_uint8 = uint8(mod(double(raw),256));

key_hex = lower(reshape( ...
    dec2hex(digest_uint8,2).',1,[]));

end

function bytes = pack_bits_msb_first(bits)

bits = logical(bits(:)');

padding = mod(8-mod(numel(bits),8),8);

bits_padded = [bits false(1,padding)];

bit_matrix = reshape(bits_padded,8,[])';

weights = 2.^(7:-1:0);

bytes = uint8(double(bit_matrix)*weights');

end

%% =========================================================================
% LOCAL FUNCTION: INTER-DEVICE HD
% =========================================================================

function [hd_percent,device_1,device_2] = ...
    calculate_interdevice_hd(responses,device_ids)

n_devices = size(responses,1);
n_pairs = n_devices*(n_devices-1)/2;

hd_percent = nan(n_pairs,1);
device_1 = nan(n_pairs,1);
device_2 = nan(n_pairs,1);

row = 0;

for i = 1:n_devices-1
    for j = i+1:n_devices

        row = row + 1;

        device_1(row) = device_ids(i);
        device_2(row) = device_ids(j);

        hd_percent(row) = ...
            100 * mean(xor(responses(i,:),responses(j,:)));
    end
end

end

function [hd_percent,mutual_count,device_1,device_2] = ...
    calculate_mutual_selected_hd( ...
    responses,masks,device_ids)

n_devices = numel(device_ids);
n_pairs = n_devices*(n_devices-1)/2;

hd_percent = nan(n_pairs,1);
mutual_count = nan(n_pairs,1);
device_1 = nan(n_pairs,1);
device_2 = nan(n_pairs,1);

row = 0;

for a = 1:n_devices-1
    for b = a+1:n_devices

        row = row + 1;

        i = device_ids(a);
        j = device_ids(b);

        mutual = masks(i,:) & masks(j,:);

        mutual_count(row) = sum(mutual);
        device_1(row) = i;
        device_2(row) = j;

        if mutual_count(row) > 0
            hd_percent(row) = 100 * mean( ...
                xor(responses(i,mutual),responses(j,mutual)));
        end
    end
end

end

%% =========================================================================
% LOCAL FUNCTION: FIGURES
% =========================================================================

function create_population_figures( ...
    cfg,chip_summary,condition_table,corner_summary,raw_hd_percent)

fig1 = figure('Visible',cfg.figure_visible);
histogram( ...
    chip_summary.positions_meeting_threshold( ...
    isfinite(chip_summary.positions_meeting_threshold)));
hold on;
yl = ylim;
plot([cfg.selected_response_length cfg.selected_response_length], ...
    yl,'--','LineWidth',1.2);
hold off;
xlabel('Positions with nominal margin \geq 0.5%');
ylabel('Number of devices');
title('Enrollment-eligible response positions');
grid on;
save_figure_compat(fig1,fullfile(cfg.output_dir, ...
    'positions_meeting_margin_threshold.png'));

fig2 = figure('Visible',cfg.figure_visible);
plot(chip_summary.chip_id, ...
    chip_summary.raw_worst_non_nominal_errors,'o-');
hold on;
plot(chip_summary.chip_id, ...
    chip_summary.selected_worst_non_nominal_errors,'x-');
plot(chip_summary.chip_id, ...
    bch_line(cfg.n_chips,8),'--');
hold off;
xlabel('Fixed-mismatch simulated device');
ylabel('Worst non-nominal response errors');
legend('Raw 1023-bit response','Selected top-950 response', ...
    'BCH t=8','Location','best');
title('Raw and stabilized worst-case PVT errors');
grid on;
save_figure_compat(fig2,fullfile(cfg.output_dir, ...
    'raw_vs_top950_worst_errors.png'));

selected_non_nominal = ...
    condition_table.selected_response_errors( ...
    ~condition_table.is_nominal & ...
    isfinite(condition_table.selected_response_errors));

fig3 = figure('Visible',cfg.figure_visible);
histogram(selected_non_nominal);
hold on;
yl = ylim;
plot([8 8],yl,'--','LineWidth',1.2);
hold off;
xlabel('Top-950 response errors');
ylabel('Number of non-nominal device-condition tests');
title('Selected-response PVT error distribution');
grid on;
save_figure_compat(fig3,fullfile(cfg.output_dir, ...
    'top950_error_distribution.png'));

labels = compose('%.1fV,%gC', ...
    corner_summary.vdd_v,corner_summary.temp_c);

fig4 = figure('Visible',cfg.figure_visible);
bar(corner_summary.worst_selected_errors);
hold on;
plot(1:height(corner_summary), ...
    8*ones(height(corner_summary),1),'--','LineWidth',1.2);
hold off;
xticks(1:height(corner_summary));
xticklabels(labels);
xtickangle(45);
xlabel('PVT condition');
ylabel('Worst top-950 error count');
title('Worst selected-response error by PVT condition');
grid on;
save_figure_compat(fig4,fullfile(cfg.output_dir, ...
    'worst_selected_errors_by_PVT_corner.png'));

fig5 = figure('Visible',cfg.figure_visible);
bar(corner_summary.success_percent_out_of_100_devices);
ylim([0 105]);
xticks(1:height(corner_summary));
xticklabels(labels);
xtickangle(45);
xlabel('PVT condition');
ylabel('Successful key reconstruction (%)');
title('Population key-reconstruction success by PVT condition');
grid on;
save_figure_compat(fig5,fullfile(cfg.output_dir, ...
    'key_success_by_PVT_corner.png'));

fig6 = figure('Visible',cfg.figure_visible);
histogram(raw_hd_percent);
xlabel('Nominal inter-device Hamming distance (%)');
ylabel('Number of device pairs');
title('Inter-device HD across the 100-device PVT population');
grid on;
save_figure_compat(fig6,fullfile(cfg.output_dir, ...
    'PVT_population_interdevice_HD.png'));

end

function values = bch_line(n,value)
values = value*ones(n,1);
end

function save_figure_compat(fig,file_name)

try
    if exist('exportgraphics','file') == 2
        exportgraphics(fig,file_name,'Resolution',300);
    else
        print(fig,file_name,'-dpng','-r300');
    end
catch
    saveas(fig,file_name);
end

close(fig);

end

%% =========================================================================
% LOCAL FUNCTION: STATISTICS
% =========================================================================

function value = finite_mean(x)
x = x(isfinite(x));

if isempty(x)
    value = NaN;
else
    value = mean(x);
end
end

function value = finite_median(x)
x = x(isfinite(x));

if isempty(x)
    value = NaN;
else
    value = median(x);
end
end

function value = finite_min(x)
x = x(isfinite(x));

if isempty(x)
    value = NaN;
else
    value = min(x);
end
end

function value = finite_max(x)
x = x(isfinite(x));

if isempty(x)
    value = NaN;
else
    value = max(x);
end
end

function value = percentile_value(x,p)

x = sort(x(isfinite(x)));

if isempty(x)
    value = NaN;
    return;
end

if numel(x) == 1
    value = x(1);
    return;
end

position = 1 + (numel(x)-1)*(p/100);

lower_index = floor(position);
upper_index = ceil(position);

if lower_index == upper_index
    value = x(lower_index);
else
    fraction = position-lower_index;

    value = ...
        x(lower_index)*(1-fraction) + ...
        x(upper_index)*fraction;
end

end

function [lower,upper] = wilson_interval(successes,trials,alpha)

if trials <= 0
    lower = NaN;
    upper = NaN;
    return;
end

% 95% interval. Avoids requiring Statistics Toolbox.
if abs(alpha-0.05) < 1e-12
    z = 1.95996398454005;
else
    z = 1.95996398454005;
end

p = successes/trials;

denominator = 1 + z^2/trials;

center = ...
    (p + z^2/(2*trials)) / denominator;

half_width = ...
    z * sqrt( ...
    p*(1-p)/trials + z^2/(4*trials^2)) / ...
    denominator;

lower = max(0,center-half_width);
upper = min(1,center+half_width);

end

function text = number_text(value)

if isfinite(value)
    text = sprintf('%.0f',value);
else
    text = 'N/A';
end

end